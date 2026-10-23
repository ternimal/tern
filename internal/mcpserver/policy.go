// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// Policy decides what a model may do on one target. It matches argv tokens,
// never a shell string, so quoting and metacharacters cannot smuggle a second
// command past it; on Windows, where a batch file's arguments go through
// cmd.exe, the agent refuses the ones cmd.exe would read as syntax (see
// tern.checkBatchArgs). It constrains the model; it is not a sandbox: the agent
// still trusts any authenticated client, so run ternd as a least-privileged
// user on hosts that matter.
type Policy struct {
	Profile         string
	allow           [][]string
	readAllow       []string
	userRead        []string // the read patterns profiles added to readonly's
	worldOnly       []string // built-in read patterns that reach only files every user may read
	writeAllow      []string
	allowShell      bool
	allowWrappers   bool
	userRun         bool // has run patterns beyond the built-in readonly set
	allowPTY        bool
	confirm         map[string]bool // actions that need a human's approval
	confirmUnlisted bool            // unlisted commands ask instead of failing
	timeoutCap      time.Duration   // 0: the server's cap
	outputCap       int             // 0: the server's cap
	ptyMax          int             // 0: defaultPTYsPerTarget
	ptyIdle         time.Duration   // 0: defaultPTYIdle
}

// Decision is a policy verdict for one action.
type Decision int

const (
	Deny    Decision = iota // refuse
	Allow                   // run without asking
	Confirm                 // run only after a human approves this exact action
)

// confirmable lists what a profile's confirm list may name.
var confirmable = map[string]bool{
	"run": true, "run:shell": true, "read_file": true, "write_file": true, "upload": true, "download": true,
	"pty_open": true,
}

// Hard bounds for profile limits.
const (
	maxProfileTimeout = 24 * time.Hour
	maxProfileOutput  = 16 << 20
)

func readonlyPolicy() *Policy {
	return &Policy{Profile: "readonly", allow: readonlyAllow, readAllow: readonlyRead, worldOnly: worldReadableRead}
}

// NewPolicy returns a built-in profile. Only "readonly" is built in; other
// profiles come from the config file through BuildPolicies.
func NewPolicy(profile string) (*Policy, error) {
	if profile == "" || profile == "readonly" {
		return readonlyPolicy(), nil
	}
	return nil, fmt.Errorf("unknown profile %q (built in: readonly; define others in the config file)", profile)
}

// ProfileConfig is a user-defined profile from the config file. It starts from
// the profile it extends (readonly by default) and only adds to it. Secret
// paths stay denied and cannot be re-enabled.
type ProfileConfig struct {
	Extends    string    `json:"extends,omitempty"`
	Run        RunConfig `json:"run,omitzero"`
	ReadPaths  []string  `json:"read_paths,omitempty"`
	WritePaths []string  `json:"write_paths,omitempty"`
	// Confirm names actions that need a human's approval each time: run,
	// run:shell, read_file, write_file, upload, download, pty_open. A profile
	// keeps the confirmations of the one it extends; extending cannot remove
	// them. write_file and upload write the same remote files, and read_file
	// and download read them, so naming one of a pair confirms both.
	Confirm []string `json:"confirm,omitempty"`
	Limits  Limits   `json:"limits,omitzero"`
	// PTY lets the model open interactive terminals (the pty_* tools). A
	// terminal runs whatever is typed into it, so this needs run.shell, and
	// where shell commands need approval (run or run:shell in confirm), so
	// does everything typed into a terminal.
	PTY bool `json:"pty,omitempty"`
}

// RunConfig adds to what run may execute.
type RunConfig struct {
	// Allow lists extra argv patterns: "*" matches one argument, a final "**"
	// any number of arguments.
	Allow [][]string `json:"allow,omitempty"`
	// Shell lets run take a whole command line through sh -c or cmd /c.
	// The policy cannot see inside a shell string, so this trusts the model
	// with anything the agent's user can do.
	Shell bool `json:"shell,omitempty"`
	// AllowWrappers lets an allow pattern with a slot (* or **) name a
	// shell, interpreter or exec-style wrapper, which can run arbitrary code
	// by itself. A pattern without one may name a wrapper anyway: it runs
	// one fixed command line.
	AllowWrappers bool `json:"allow_wrappers,omitempty"`
	// ConfirmUnlisted lets a command outside the allowlist run once a human
	// approves it, instead of being refused. Wrappers stay refused unless
	// AllowWrappers is set.
	ConfirmUnlisted bool `json:"confirm_unlisted,omitempty"`
}

// Limits overrides the server's caps for one profile.
type Limits struct {
	TimeoutS    int `json:"timeout_s,omitempty"`
	OutputBytes int `json:"output_bytes,omitempty"`
	// Terminals caps the terminals open at once on a target, 1 to 16;
	// default 4. TerminalIdleS closes a terminal no call has used for that
	// many seconds, 60 to 86400; default 600.
	Terminals     int `json:"terminals,omitempty"`
	TerminalIdleS int `json:"terminal_idle_s,omitempty"`
}

// BuildPolicies resolves user profiles, following extends chains, on top of
// the built-in readonly profile.
func BuildPolicies(user map[string]ProfileConfig) (map[string]*Policy, error) {
	if _, ok := user["readonly"]; ok {
		return nil, fmt.Errorf(`profile "readonly" is built in and cannot be redefined`)
	}
	out := map[string]*Policy{"readonly": readonlyPolicy()}
	var build func(name string, chain []string) (*Policy, error)
	build = func(name string, chain []string) (*Policy, error) {
		if p, ok := out[name]; ok {
			return p, nil
		}
		cfg, ok := user[name]
		if !ok {
			return nil, fmt.Errorf("unknown profile %q", name)
		}
		if slices.Contains(chain, name) {
			return nil, fmt.Errorf("profile cycle: %s", strings.Join(append(chain, name), " -> "))
		}
		parentName := cfg.Extends
		if parentName == "" {
			parentName = "readonly"
		}
		parent, err := build(parentName, append(chain, name))
		if err != nil {
			return nil, err
		}
		p := &Policy{
			Profile:         name,
			allow:           slices.Concat(parent.allow, cfg.Run.Allow),
			readAllow:       slices.Concat(parent.readAllow, cfg.ReadPaths),
			userRead:        slices.Concat(parent.userRead, cfg.ReadPaths),
			worldOnly:       parent.worldOnly,
			writeAllow:      slices.Concat(parent.writeAllow, cfg.WritePaths),
			allowShell:      parent.allowShell || cfg.Run.Shell,
			allowWrappers:   parent.allowWrappers || cfg.Run.AllowWrappers,
			allowPTY:        parent.allowPTY || cfg.PTY,
			userRun:         parent.userRun || len(cfg.Run.Allow) > 0 || cfg.Run.ConfirmUnlisted,
			confirm:         maps.Clone(parent.confirm),
			confirmUnlisted: parent.confirmUnlisted || cfg.Run.ConfirmUnlisted,
			timeoutCap:      parent.timeoutCap,
			outputCap:       parent.outputCap,
			ptyMax:          parent.ptyMax,
			ptyIdle:         parent.ptyIdle,
		}
		if p.confirm == nil {
			p.confirm = map[string]bool{}
		}
		for _, a := range cfg.Confirm {
			p.confirm[a] = true
		}
		// Each tool of a pair reaches the same files, so confirming only one
		// would leave the model the other, unwatched.
		for _, pair := range [][2]string{{"write_file", "upload"}, {"read_file", "download"}} {
			if p.confirm[pair[0]] || p.confirm[pair[1]] {
				p.confirm[pair[0]], p.confirm[pair[1]] = true, true
			}
		}
		if err := cfg.validate(p.allowWrappers); err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		if p.allowPTY && !p.allowShell {
			return nil, fmt.Errorf("profile %q: pty needs run.shell, since a terminal runs any command typed into it", name)
		}
		if cfg.Limits.TimeoutS > 0 {
			p.timeoutCap = time.Duration(cfg.Limits.TimeoutS) * time.Second // bounded by validate
		}
		if cfg.Limits.OutputBytes > 0 {
			p.outputCap = cfg.Limits.OutputBytes
		}
		if cfg.Limits.Terminals > 0 {
			p.ptyMax = cfg.Limits.Terminals
		}
		if cfg.Limits.TerminalIdleS > 0 {
			p.ptyIdle = time.Duration(cfg.Limits.TerminalIdleS) * time.Second
		}
		out[name] = p
		return p, nil
	}
	for _, name := range slices.Sorted(maps.Keys(user)) {
		if _, err := build(name, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c ProfileConfig) validate(allowWrappers bool) error {
	for _, a := range c.Confirm {
		if !confirmable[a] {
			return fmt.Errorf("confirm entry %q is not one of: run, run:shell, read_file, write_file, upload, download, pty_open", a)
		}
	}
	for _, pat := range c.Run.Allow {
		if len(pat) == 0 || pat[0] == "" || pat[0] == "*" || pat[0] == "**" {
			return fmt.Errorf("run pattern %q must start with a command name", pat)
		}
		if why := commandNameProblem(pat[0]); why != "" {
			return fmt.Errorf("run pattern %q: the command must be a bare name, not %s", pat, why)
		}
		// A pattern with no slot runs one fixed command, whose arguments the
		// model cannot choose, so it may name a wrapper.
		if !allowWrappers && isWrapper(pat[0]) && !literalPattern(pat) {
			return fmt.Errorf("run pattern %q names a shell, interpreter or wrapper with an argument the model chooses (* or **); give every argument, or set run.allow_wrappers to allow that deliberately", pat)
		}
		for i, tok := range pat {
			if tok == "" || (tok == "**" && i != len(pat)-1) {
				return fmt.Errorf("run pattern %q: empty token, or ** before the last position", pat)
			}
		}
	}
	for _, list := range [][]string{c.ReadPaths, c.WritePaths} {
		for _, p := range list {
			if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "**") {
				return fmt.Errorf("path pattern %q must be absolute (/..., /c:/...) or start with **", p)
			}
			if strings.ContainsRune(p, 0) || slices.Contains(strings.Split(p, "/"), "..") {
				return fmt.Errorf("path pattern %q must not contain a NUL byte or a .. segment", p)
			}
		}
	}
	if c.Limits.TimeoutS < 0 || time.Duration(c.Limits.TimeoutS) > maxProfileTimeout/time.Second {
		return fmt.Errorf("limits.timeout_s must be between 0 and %d", int(maxProfileTimeout/time.Second))
	}
	if c.Limits.OutputBytes < 0 || c.Limits.OutputBytes > maxProfileOutput {
		return fmt.Errorf("limits.output_bytes must be between 0 and %d", maxProfileOutput)
	}
	if c.Limits.Terminals < 0 || c.Limits.Terminals > maxPTYs {
		return fmt.Errorf("limits.terminals must be between 0 and %d", maxPTYs)
	}
	if c.Limits.TerminalIdleS != 0 && (c.Limits.TerminalIdleS < 60 || c.Limits.TerminalIdleS > 86400) {
		return fmt.Errorf("limits.terminal_idle_s must be 0 or between 60 and 86400")
	}
	return nil
}

// Typed argument slots for the built-in patterns: a count, a name that is not
// an option, or a systemd unit: a name without the glob characters systemctl
// expands to every unit they match. A plain "*" would let the model pass an
// option there, as in "journalctl -n --vacuum-time=1s", which deletes logs.
const (
	numTok  = "\x00num"
	nameTok = "\x00name"
	unitTok = "\x00unit"
)

// unitProps are the properties systemctl show prints under readonly: what
// state a unit is in, never what it runs or is given. systemctl status is
// not offered, since its process tree prints every command line in the unit,
// which /proc/*/cmdline holds and secretPaths never lets the model read. Left
// out on purpose: the command lists (ExecStart and the other Exec* lists),
// the environment (Environment, EnvironmentFiles, PassEnvironment), the
// credentials (SetCredential, LoadCredential and their variants), the data a
// service gets on standard input (StandardInputData), a mount's options
// (Options, where a password can sit), the status text a service reports, and
// the description, which for a unit systemd-run made is its command line.
const unitProps = "Id,LoadState,ActiveState,SubState,UnitFileState,Result,MainPID,NRestarts," +
	"ActiveEnterTimestamp,ActiveExitTimestamp,StateChangeTimestamp,MemoryCurrent,TasksCurrent,FragmentPath"

// readonlyAllow lists the argv shapes the readonly profile may run on Unix
// and Windows agents. "*" matches exactly one argument and a final "**"
// matches any number of remaining arguments; other tokens match exactly.
var readonlyAllow = [][]string{
	{"cat", "/etc/os-release"},
	{"date"},
	{"df"}, {"df", "-h"},
	{"echo", "**"},
	{"free"}, {"free", "-h"}, {"free", "-m"},
	{"hostname"},
	{"id"},
	{"ipconfig"}, {"ipconfig", "/all"},
	{"journalctl", "-n", numTok},
	{"journalctl", "-u", nameTok, "-n", numTok},
	{"ls"}, {"ls", "*"}, {"ls", "*", "*"},
	{"systemctl", "is-active", unitTok}, {"systemctl", "is-failed", unitTok},
	{"systemctl", "show", "-p", unitProps, unitTok},
	{"systeminfo"},
	{"tasklist"},
	{"uname"}, {"uname", "*"},
	{"uptime"},
	{"whoami"}, {"whoami", "*"},
}

// wrappers can run arbitrary commands or code by themselves (shells,
// interpreters, exec-style wrappers and programs with shell escapes), so
// letting one through as argv[0] would defeat an allowlist. The list is best
// effort: many more programs can be made to run another one by some option,
// so an allowlist should name the commands it needs with fixed arguments
// wherever it can.
var wrappers = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "csh": true, "tcsh": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
	"wscript": true, "cscript": true, "mshta": true, "rundll32": true, "regsvr32": true,
	"env": true, "xargs": true, "nice": true, "nohup": true, "timeout": true, "stdbuf": true, "setsid": true,
	"sudo": true, "su": true, "doas": true, "busybox": true, "script": true, "expect": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true, "php": true, "lua": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true,
	"find": true, "git": true, "tar": true, "rsync": true, "ssh": true, "scp": true,
	"vi": true, "vim": true, "nvim": true, "less": true, "more": true, "man": true,
	"socat": true, "nc": true, "ncat": true, "telnet": true, "curl": true, "wget": true, "dd": true,
	"wsl": true, "py": true, "pyw": true, "tclsh": true, "wish": true, "gdb": true, "strace": true, "ltrace": true,
	"chroot": true, "nsenter": true, "unshare": true, "systemd-run": true, "pkexec": true, "runuser": true,
	"sshpass": true, "watch": true, "flock": true, "taskset": true, "ionice": true, "chrt": true, "time": true,
	"docker": true, "podman": true, "kubectl": true, "crontab": true, "at": true,
	"schtasks": true, "wmic": true, "msiexec": true, "msbuild": true, "installutil": true, "regasm": true,
	"regsvcs": true, "certutil": true, "bitsadmin": true, "forfiles": true,
	"rbash": true, "ash": true, "mksh": true, "yash": true, "posh": true,
	"nodejs": true, "npx": true, "deno": true, "bun": true, "bunx": true, "pythonw": true,
	"rscript": true, "julia": true, "osascript": true,
	"setpriv": true, "capsh": true, "sg": true, "newgrp": true, "run0": true, "firejail": true, "bwrap": true,
	"systemd-nspawn": true, "start-stop-daemon": true, "run-parts": true, "parallel": true,
	"tmux": true, "screen": true, "dtach": true, "xdg-open": true, "open": true,
	"make": true, "sqlite3": true, "ed": true, "emacs": true, "zip": true,
	"conhost": true, "winrs": true, "pcalua": true, "sc": true,
	// Programs that run a command given to them, under other limits,
	// scheduling, security context, namespace, session or architecture, or
	// on their output (split --filter, sort --compress-program).
	"split": true, "sort": true, "setarch": true, "linux32": true, "linux64": true, "x86_64": true, "i386": true,
	"uname26": true, "arch": true, "prlimit": true, "choom": true, "uclampset": true, "numactl": true, "cgexec": true,
	"runcon": true, "systemd-cat": true, "systemd-inhibit": true, "systemd-socket-activate": true, "machinectl": true,
	"dbus-run-session": true, "dbus-launch": true, "ssh-agent": true, "ip": true, "chpst": true, "setuidgid": true,
	"envdir": true, "softlimit": true, "daemonize": true, "su-to-root": true, "sudoedit": true, "caffeinate": true,
	"sandbox-exec": true, "launchctl": true, "batch": true, "entr": true, "watchexec": true, "unbuffer": true,
	"fakeroot": true, "fakechroot": true, "proot": true, "faketime": true, "proxychains": true, "torsocks": true,
	"torify": true, "xvfb-run": true, "xinit": true, "valgrind": true, "perf": true, "bpftrace": true,
	"docker-compose": true, "podman-compose": true, "nerdctl": true, "ctr": true, "crictl": true, "lxc": true,
	"incus": true,
	// Clients, editors, pagers and tools with a command escape or an option
	// that names a program to run.
	"sftp": true, "slogin": true, "ssh-copy-id": true, "autossh": true, "mosh": true, "ftp": true, "lftp": true,
	"psql": true, "mysql": true, "mariadb": true, "sqlplus": true, "mongo": true, "mongosh": true, "hg": true,
	"svn": true, "lldb": true, "tcpdump": true, "nmap": true, "ex": true, "view": true, "vimdiff": true, "rvim": true,
	"rview": true, "gvim": true, "evim": true, "editor": true, "nano": true, "pico": true, "pager": true,
	"xterm": true, "x-terminal-emulator": true, "lynx": true, "w3m": true, "fd": true, "fdfind": true, "rg": true,
	"aria2c": true, "rclone": true, "restic": true, "borg": true, "cpio": true, "gtar": true, "bsdtar": true,
	"tex": true, "latex": true, "pdflatex": true, "lualatex": true, "xelatex": true, "luatex": true, "pdftex": true,
	"groff": true, "gs": true, "convert": true, "magick": true,
	// GNU tools under the names Homebrew and BSD packages give them.
	"gsed": true, "gfind": true, "gxargs": true, "genv": true, "gtimeout": true, "gstdbuf": true, "gmake": true,
	"gm4": true,
	// Other shells, interpreters and read-eval-print loops.
	"lksh": true, "rksh": true, "netcat": true, "pypy": true, "luajit": true, "m4": true, "dc": true,
	"gnuplot": true, "r": true, "irb": true, "erb": true, "jruby": true, "ipython": true, "jupyter": true,
	"jshell": true, "jrunscript": true, "jjs": true, "groovy": true, "groovysh": true, "scala": true, "kotlin": true,
	"kotlinc": true, "clojure": true, "clj": true, "guile": true, "racket": true, "sbcl": true, "clisp": true,
	"erl": true, "escript": true, "elixir": true, "iex": true, "swipl": true, "ghci": true, "runghc": true,
	"runhaskell": true, "octave": true, "calc": true, "csi": true, "fsi": true, "dotnet": true, "qjs": true,
	"tcc": true,
	// Build and package tools, which run the code of a project or package.
	"npm": true, "pnpm": true, "yarn": true, "corepack": true, "pip": true, "pipx": true, "uv": true, "uvx": true,
	"poetry": true, "pipenv": true, "pdm": true, "hatch": true, "tox": true, "nox": true, "conda": true,
	"mamba": true, "micromamba": true, "bundle": true, "bundler": true, "rake": true, "gem": true, "composer": true,
	"cargo": true, "go": true, "mvn": true, "gradle": true, "ant": true, "sbt": true, "lein": true, "cmake": true,
	"ninja": true, "meson": true, "scons": true, "bazel": true, "bazelisk": true, "bmake": true, "gcc": true,
	"cc": true, "g++": true, "c++": true, "clang": true, "clang++": true, "rpm": true, "rpmbuild": true, "dnf": true,
	"yum": true, "apt": true, "apt-get": true, "aptitude": true, "dpkg": true, "apk": true, "zypper": true,
	"pacman": true, "emerge": true, "brew": true, "snap": true, "flatpak": true, "nix": true, "nix-shell": true,
	"nix-env": true, "guix": true, "pkg": true,
	// Windows programs that run commands, scripts or DLLs they are given, or
	// start other programs.
	"explorer": true, "runas": true, "wt": true, "mintty": true, "git-bash": true, "git-cmd": true, "cdb": true,
	"windbg": true, "ntsd": true, "psexec": true, "syncappvpublishingserver": true, "scriptrunner": true,
	"odbcconf": true, "cmstp": true, "control": true, "msedge": true, "chrome": true, "ubuntu": true, "debian": true,
	"kali": true, "diskshadow": true, "netsh": true, "reg": true, "regedit": true, "regini": true,
	"presentationhost": true, "msdt": true, "hh": true, "infdefaultinstall": true, "mavinject": true, "msxsl": true,
	"pcwrun": true, "runscripthelper": true, "xwizard": true, "atbroker": true, "dnscmd": true, "esentutl": true,
	"mmc": true, "powershell_ise": true, "wuauclt": true, "verclsid": true, "certreq": true, "ieexec": true,
	"ntdsutil": true,
	// Interpreters, read-eval-print loops and database shells with a command
	// escape, and other names of listed ones.
	"java": true, "javaw": true, "ghc": true, "raku": true, "crystal": true, "bb": true, "mix": true, "ocaml": true,
	"micropython": true, "bpython": true, "xonsh": true, "nu": true, "elvish": true, "oksh": true, "sash": true,
	"toybox": true, "swift": true, "mlr": true, "duckdb": true, "sqlcmd": true, "mysqlsh": true, "mycli": true,
	"usql": true, "spatialite": true, "fennel": true, "resty": true, "ecl": true, "rhino": true, "jbang": true,
	"plackup": true, "rackup": true, "latexmk": true, "etex": true, "xetex": true, "mpost": true, "texlua": true,
	"luahbtex": true, "yarnpkg": true, "pnpx": true, "pdb": true, "kak": true, "nvi": true, "lxc-attach": true,
	"lxc-execute": true,
	// Programs that run the command they are given, or a project's or a
	// tool's own code, and version, deployment and container managers.
	"eatmydata": true, "rlwrap": true, "chronic": true, "ifne": true, "pee": true, "zrun": true, "lckdo": true,
	"mispipe": true, "hyperfine": true, "rr": true, "catchsegv": true, "datefudge": true, "trickle": true,
	"nocache": true, "zellij": true, "abduco": true, "nodemon": true, "pm2": true, "foreman": true,
	"coredumpctl": true, "busctl": true, "mise": true, "asdf": true, "direnv": true, "pyenv": true, "rbenv": true,
	"opam": true, "volta": true, "fnm": true, "pixi": true, "rye": true, "carton": true, "perlbrew": true, "nx": true,
	"lerna": true, "concurrently": true, "prove": true, "perldoc": true, "cpan": true, "cpanm": true, "gh": true,
	"glab": true, "jj": true, "repo": true, "ansible": true, "ansible-playbook": true, "ansible-pull": true,
	"salt-call": true, "puppet": true, "chef-apply": true, "chef-client": true, "chef-solo": true, "knife": true,
	"helm": true, "kustomize": true, "buildah": true, "runc": true, "crun": true, "multipass": true, "vagrant": true,
	"limactl": true, "colima": true, "minikube": true, "wp": true, "drush": true, "dbclient": true, "plink": true,
	// Windows programs known to run code or programs they are handed.
	"wlrmdr": true, "tttracer": true, "winget": true, "choco": true, "fsianycpu": true, "rcsi": true,
	"tracker": true, "mftrace": true, "appvlp": true, "sqlps": true,
	// Programs that run the command they are given under an AppArmor
	// profile, a CPU limit, a lock, a sandbox, a tracer or another user, on a
	// new virtual console, in a container or on the host from inside one, by
	// synthesized keystrokes, as an init script (service NAME runs
	// /etc/init.d/NAME, a NAME with ../ included), or as a mail program's or
	// viewer's command; programs that run a project's tasks or hooks, or a
	// script or source file; other shells; and the Windows programs that run
	// the commands, programs or code they are handed, compilers included.
	"aa-exec": true, "logsave": true, "cpulimit": true, "pidstat": true, "setlock": true, "msgfilter": true,
	"openvt": true, "ksu": true, "uftrace": true, "hwloc-bind": true, "minijail0": true, "nsjail": true,
	"distrobox": true, "distrobox-enter": true, "toolbox": true, "flatpak-spawn": true, "oc": true, "xdotool": true,
	"service": true, "mail": true, "mailx": true, "run-mailcap": true, "distcc": true, "just": true,
	"pre-commit": true, "tsx": true, "ts-node": true, "electron": true, "gosh": true, "nim": true, "zig": true,
	"pdksh": true, "osh": true, "ysh": true,
	"runonce": true, "msdeploy": true, "ttdinject": true, "vsjitdebugger": true, "csc": true, "vbc": true, "jsc": true,
	// Programs that load a shared library they are given, which runs as
	// code: openssl -engine or -provider, ssh-keygen -D, pkcs11-tool
	// --module, p11tool and certtool --provider, p11-kit remote, every JDK
	// tool (a -J-agentpath: option anywhere on its command line, and jcmd's
	// JVMTI.agent_load), redis-server, valkey-server and keydb-server
	// --loadmodule, nginx -g 'load_module ...', Apache's -C 'LoadModule ...',
	// and insmod and modprobe (a kernel module, or modprobe -C's install
	// commands); and programs that run a program they are given: gpg's
	// --photo-viewer, gpg-agent's daemon command, gpg-connect-agent --exec,
	// openvpn --up and stunnel's exec.
	"openssl": true, "ssh-keygen": true, "pkcs11-tool": true, "p11tool": true, "certtool": true, "p11-kit": true,
	"keytool": true, "jarsigner": true, "javac": true, "javadoc": true, "javap": true, "javah": true, "jar": true,
	"jcmd": true, "jconsole": true, "jdb": true, "jdeprscan": true, "jdeps": true, "jfr": true, "jhsdb": true,
	"jimage": true, "jinfo": true, "jlink": true, "jmap": true, "jmod": true, "jnativescan": true, "jpackage": true,
	"jps": true, "jstack": true, "jstat": true, "jstatd": true, "jwebserver": true, "rmiregistry": true,
	"serialver": true, "jhat": true, "jmc": true, "jvisualvm": true, "jsadebugd": true, "javaws": true,
	"javapackager": true, "appletviewer": true, "extcheck": true, "idlj": true, "native2ascii": true, "orbd": true,
	"pack200": true, "unpack200": true, "policytool": true, "rmic": true, "rmid": true, "schemagen": true,
	"servertool": true, "tnameserv": true, "wsgen": true, "wsimport": true, "xjc": true, "jabswitch": true,
	"jaccessinspector": true, "jaccesswalker": true,
	"redis-server": true, "valkey-server": true, "keydb-server": true, "nginx": true, "nginx-debug": true,
	"openresty": true, "angie": true, "apache2": true, "httpd": true, "apachectl": true, "apache2ctl": true,
	"insmod": true, "modprobe": true, "gpg": true, "gpg2": true, "gpg-agent": true, "gpg-connect-agent": true,
	"openvpn": true, "stunnel": true, "stunnel4": true,
	// ldd, which may run the program it is given to list its libraries, and
	// database servers started with a library to preload (postgres -c
	// shared_preload_libraries=..., mysqld --plugin-load=...).
	"ldd": true, "postgres": true, "postmaster": true, "pg_ctl": true, "pg_ctlcluster": true, "mysqld": true,
	"mariadbd": true, "mysqld_safe": true, "mariadbd-safe": true,
}

// isWrapper reports whether name runs a wrapper, also under another spelling
// of it: a Windows executable extension (bash.exe), a version or build suffix
// (python3.12, perl5.40-x86_64-linux-gnu, python3.13-dbg, bash-static,
// php-cgi), a Debian alternative's suffix (vim.basic, nc.openbsd), a prefix
// such as a cross compiler's (x86_64-linux-gnu-gcc, bsd-csh), a Windows
// drive-relative name or data stream (C:cmd, cmd.exe::$DATA), or a spelling
// a case-insensitive file system opens as it (see fold).
func isWrapper(name string) bool {
	base := name[strings.LastIndexAny(name, `/\`)+1:]
	for _, part := range strings.Split(base, ":") {
		if wrapperForm(strings.ToLower(part)) || wrapperForm(fold(part)) {
			return true
		}
	}
	return false
}

// wrapperForm reports whether n, in lowercase, names a wrapper or a variant
// of one.
func wrapperForm(n string) bool {
	for {
		// Windows drops trailing dots and spaces, so "cmd.exe ." runs cmd.exe.
		n = strings.TrimRight(n, " .")
		if wrapperName(n) {
			return true
		}
		for i := range len(n) {
			if n[i] == '-' && wrapperName(n[i+1:]) {
				return true
			}
		}
		t := trimVariant(n)
		if t == n {
			return false
		}
		n = t
	}
}

// wrapperName reports a wrapper's name, alone or with a version: python3.12,
// gcc-13.
func wrapperName(n string) bool {
	return wrappers[n] || wrappers[strings.TrimRight(n, "0123456789.-")]
}

// trimVariant drops one suffix that marks a variant of a program: a multiarch
// triplet (perl5.40-x86_64-linux-gnu), an extension, alternative or version
// after a dot (bash.exe, vim.basic, python3.12), or a build's or edition's
// (bash-static, python3.13-dbg, php-cgi, gdb-multiarch, emacs-gtk, scala-cli,
// jupyter-console, pwsh-preview, kotlinc-jvm). It returns n when there is
// none.
func trimVariant(n string) string {
	if i := strings.Index(n, "-linux-"); i > 0 && !strings.Contains(n[i+len("-linux-"):], "-") {
		if j := strings.LastIndexByte(n[:i], '-'); j > 0 {
			return n[:j]
		}
	}
	if i := strings.LastIndexByte(n, '.'); i > 0 {
		return n[:i]
	}
	for _, s := range []string{"-static", "-dbg", "-cgi", "-multiarch", "-nox", "-gtk", "-gtk3", "-lucid", "-athena",
		"-cli", "-console", "-preview", "-jvm"} {
		if t, ok := strings.CutSuffix(n, s); ok && t != "" {
			return t
		}
	}
	return n
}

// commandNameProblem says why name is not a bare command name: a path, a
// drive-relative path or data stream (C:cmd, cmd.exe::$DATA), or an 8.3
// short name (POWERS~1). A Windows agent runs each as a program the rules
// cannot see by its name: C:cmd is cmd.exe in that drive's current
// directory, and a short name stands for a long one.
func commandNameProblem(name string) string {
	switch {
	case strings.ContainsAny(name, `/\`):
		return "a path"
	case strings.ContainsRune(name, ':'):
		return "a drive-relative path or a data stream"
	case hasShortNameTilde(name):
		return "a Windows 8.3 short name"
	}
	return ""
}

// hasShortNameTilde reports a "~" followed by a digit, as 8.3 short names
// have: PROGRA~1, POWERS~1.EXE.
func hasShortNameTilde(name string) bool {
	for i := 0; i+1 < len(name); i++ {
		if name[i] == '~' && name[i+1] >= '0' && name[i+1] <= '9' {
			return true
		}
	}
	return false
}

// readonlyRead lists what read_file may open in the readonly profile:
// configuration and logs, plus a few diagnostic /proc files, and the Windows
// equivalents. Windows patterns are lowercase; Windows paths match without case.
var readonlyRead = []string{
	"/etc/**",
	"/var/log/**",
	"/proc/cpuinfo", "/proc/loadavg", "/proc/meminfo", "/proc/mounts", "/proc/uptime", "/proc/version",
	"/proc/*/status",
	"/*:/windows/system32/drivers/etc/hosts",
	"/*:/windows/logs/**",
	"/*:/windows/system32/logfiles/**",
}

// worldReadableRead lists the readonly read patterns that reach only files
// every user may read. /etc holds configuration anyone may read, beside the
// credential files of many services (sssd.conf, smbpasswd,
// wpa_supplicant.conf and more than secretPaths can name), which only their
// owner or group may read, or which sit in a directory only they may enter,
// and which a ternd running as root would otherwise hand over. A profile that
// names a path itself reads it whatever its mode.
// Logs are not limited: they are commonly readable only by a group such as
// adm, and reading them is what readonly is for.
var worldReadableRead = []string{"/etc/**"}

// secretPaths are never readable or writable, whatever a profile allows:
// credential stores, private keys, the sudoers files and process memory or
// environment. They match without regard to case, also as a case-insensitive
// file system compares names (see fold), so a renamed-case copy of a key file,
// or a spelling such a file system opens as a protected name, is still
// caught. Places where a file runs code or grants access later are in
// noWritePaths.
var secretPaths = []string{
	// The password hashes, under the names their backups get too (shadow-,
	// gshadow-, shadow.bak, Debian's daily /var/backups/shadow.bak).
	"/etc/shadow", "/etc/*shadow*", "/var/backups/*shadow*",
	"/etc/sudoers", "/etc/sudoers.d/**",
	"/etc/ssh/*_key", "/etc/ssl/private/**", "/etc/letsencrypt/**", "/etc/wireguard/**",
	"**/.ssh/**", "**/.gnupg/**", "**/.aws/**", "**/.azure/**", "**/.config/gcloud/**", "**/.kube/**",
	"**/.docker/config.json", "**/.netrc", "**/.git-credentials", "**/.pgpass", "**/.env", "**/.env.*",
	"**/*.key", "**/*.pem", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore", "**/*.kdbx",
	"**/*secret*", "**/*credential*", "**/*token*",
	"/proc/*/environ", "/proc/*/cmdline", "/proc/*/mem", "/proc/*/maps", "/proc/kcore",
	// Links back into the whole file system or another process: /proc/1/root/etc/shadow.
	"/proc/*/root/**", "/proc/*/cwd/**", "/proc/*/fd/**", "/proc/*/task/**", "/proc/*/map_files/**",
	"/etc/kubernetes/*.conf", "/etc/kubernetes/pki/**", "/etc/rancher/**", "**/kubeconfig", "**/*.kubeconfig",
	"**/*.keytab", "/etc/security/opasswd", "/etc/networkmanager/system-connections/**",
	"/*:/windows/system32/config/**", "/*:/windows/repair/**", "/*:/windows/panther/**",
	"**/unattend.xml", "**/sysprep.inf", "**/ntds.dit",
	"**/appdata/*/microsoft/credentials/**", "**/appdata/*/microsoft/protect/**",
	"**/appdata/*/microsoft/crypto/**", "**/appdata/*/microsoft/vault/**",
	"/*:/programdata/microsoft/crypto/**", "/*:/programdata/ssh/**",
	// Credential stores of package and container registries, mail relays,
	// databases, sync tools and browsers, shell histories, and Windows system
	// secrets (the machine's DPAPI keys, Wi-Fi profiles, registry hives, crash
	// dumps, IIS configuration).
	"/etc/apt/auth.conf", "/etc/apt/auth.conf.d/**", "/etc/postfix/sasl_passwd*", "/etc/exim4/passwd*",
	"/etc/fetchmailrc", "/etc/mysql/debian.cnf", "**/*.keyring", "/etc/dropbear/**", "/etc/docker/key.json",
	"**/.dockercfg", "**/containers/auth.json", "**/.npmrc", "**/.pypirc", "**/.my.cnf", "**/_netrc",
	"**/rclone.conf", "**/sops/age/keys.txt",
	"**/*.ppk", "**/*.pvk", "**/*.ovpn", "**/*.rdp",
	"**/logins.json", "**/key3.db", "**/key4.db", "**/cookies.sqlite", "**/cookies",
	"**/login data", "**/login data for account", "**/local state",
	"**/.*_history", "**/psreadline/consolehost_history.txt",
	"**/filezilla/sitemanager.xml", "**/filezilla/recentservers.xml",
	"/*:/windows/system32/microsoft/protect/**", "/*:/programdata/microsoft/vault/**",
	"/*:/programdata/microsoft/wlansvc/profiles/**", "**/ntuser.dat*", "**/usrclass.dat*",
	"/*:/windows/memory.dmp", "/*:/windows/minidump/**", "/*:/windows/system32/inetsrv/config/**",
	// A directory named for secrets holds them under any file name:
	// Kubernetes secret volumes, Docker's /run/secrets, systemd credentials.
	"**/*secret*/**", "**/*credential*/**", "**/*token*/**", "**/.dockerconfigjson",
	// Service credentials kept under /etc: directory, LDAP bind and Kerberos
	// master keys, Samba, Redis and Wi-Fi passwords, VPN and web logins, mail
	// relays, SNMP communities, NTP keys, and BSD and macOS password stores.
	"/etc/sssd/**", "/etc/nslcd.conf", "/etc/ldap.conf", "/etc/pam_ldap.conf", "/etc/libnss-ldap.conf",
	"/etc/ldap/slapd.d/**", "/etc/openldap/slapd.d/**", "/etc/openldap/certs/password",
	"/etc/krb5kdc/**", "/var/kerberos/krb5kdc/**", "**/.k5.*", "**/smbpasswd", "**/passdb.tdb",
	"/etc/redis.conf", "/etc/redis/**", "/etc/valkey/**", "**/wpa_supplicant*.conf", "/var/lib/iwd/**",
	"/etc/openvpn/**/*.txt", "**/.htpasswd*", "**/htpasswd", "**/.htdigest*",
	"/etc/ssmtp/**", "**/msmtprc", "**/.msmtprc", "**/pgbouncer/userlist.txt", "/etc/dovecot/users",
	"/etc/dovecot/passwd*", "/etc/webmin/miniserv.users", "/etc/gitlab/**", "**/gitlab-runner/config.toml",
	"**/.gitlab-runner/config.toml", "**/snmpd.conf", "**/snmptrapd.conf", "**/chrony.keys", "/etc/ntp.keys",
	"/etc/ntp/keys", "/etc/nut/upsd.users", "/etc/nut/upsmon.conf", "/etc/pki/tls/private/**",
	"/etc/kcpassword", "/etc/master.passwd", "/etc/spwd.db",
	// systemd's credential stores, which LoadCredential= reads (/etc,
	// /run, /usr/lib and /usr/local/lib each have one, and an .encrypted
	// twin), and its runtime credentials, which *credential* catches.
	"**/credstore/**", "**/credstore.encrypted/**",
	// Installer and cloud-init answers, which hold the first user's password.
	"/var/log/installer/autoinstall-user-data*", "/var/lib/cloud/**/user-data*",
	// macOS password hashes (its /etc/shadow) and keychains, desktop
	// keyrings, and SSSD's cached password hashes.
	"/var/db/dslocal/**", "/var/db/SystemKey", "**/Library/Keychains/**", "**/.local/share/keyrings/**",
	"**/.local/share/kwalletd/**", "/var/lib/sss/db/**",
	// Command-line tools' tokens and shell histories the rules above miss.
	"**/.config/gh/hosts.yml", "**/.config/glab-cli/config.yml", "**/.s3cfg", "**/.boto", "**/.config/doctl/config.yaml",
	"**/.local/share/fish/fish_history", "**/.histfile", "**/.zhistory", "**/.local/share/atuin/**",
	// VPN logins, FreeBSD's sudoers, and application secrets: WordPress's
	// database password, Terraform state and variables, and env files for
	// docker compose (env_file) and direnv.
	"/etc/vpnc/**", "/usr/local/etc/sudoers", "/usr/local/etc/sudoers.d/**", "**/wp-config.php", "**/*.tfstate",
	"**/*.tfstate.backup", "**/*.tfvars", "**/*.tfvars.json", "**/*.env", "**/.envrc",
	// OpenSSH private keys under their default names wherever they are kept
	// (their .pub twins too, which the model rarely needs), Kerberos ticket
	// caches, the Erlang cookie (whoever has it runs code on the node),
	// Tailscale's node keys, etcd's data (every Secret of a Kubernetes
	// cluster), Ceph daemon keyrings, and the passwords of fetchmail, MySQL
	// login paths, Maven's master password and Ansible vault password files;
	// vim's and neovim's history of commands and registers, as shell
	// histories are.
	"**/id_rsa*", "**/id_dsa*", "**/id_ecdsa*", "**/id_ed25519*", "**/id_xmss*", "**/krb5cc*", "**/krb5cc*/**",
	"**/.erlang.cookie", "**/tailscaled.state", "/*:/programdata/tailscale/**", "/var/lib/etcd/**",
	"**/member/snap/**", "**/member/wal/**", "/var/lib/ceph/**/keyring", "**/.fetchmailrc", "**/.mylogin.cnf",
	"**/.m2/settings-security.xml", "**/*vault?pass*", "**/*vaultpass*", "**/.viminfo*", "**/nvim/shada/**",
	// Registry and package-manager logins the rules above miss: Composer's,
	// Maven's server passwords, Gradle's and Yarn's tokens, Poetry's, NuGet's,
	// pip's index URLs, Bundler's, Helm's registry and repository logins,
	// JFrog's, Terraform's CLI tokens, hub's, and the registry logins of
	// root's podman, buildah and skopeo under /run/containers/0.
	"**/.composer/auth.json", "**/composer/auth.json", "**/.m2/settings.xml", "**/.gradle/gradle.properties",
	"**/.yarnrc.yml", "**/pypoetry/auth.toml", "**/nuget/nuget.config", "**/pip.conf", "**/pip.ini",
	"**/.bundle/config", "**/helm/registry/config.json", "**/helm/repositories.yaml", "**/.jfrog/**",
	"**/.terraformrc", "**/terraform.rc", "**/.config/hub", "/run/containers/*/auth.json",
	// tern's own keys, under the names tern keygen and the docs give them,
	// and its configuration and state directories: token and key files, the
	// config file, the audit log, recordings, and the terminal state file,
	// which makes the next tern mcp reattach the sessions it names.
	"**/tern_id_*", "**/id_tern*", "**/.config/tern/**", "**/.local/state/tern/**", "**/appdata/local/tern/**",
	"**/appdata/roaming/tern/**", "**/Library/Application Support/tern/**",
	// MCP clients' and AI coding tools' configuration that holds logins or
	// the environment their MCP servers get, such as TERN_TOKEN: Claude
	// Code's directories (settings with env, .credentials.json, transcripts)
	// and ~/.claude.json, Claude Desktop's server list, every MCP server list
	// (mcp.json, .mcp.json, and Windsurf's, Copilot CLI's and Cline's), the
	// Anthropic API's profiles, and Codex's and Gemini CLI's directories.
	// They also run code (see noWritePaths), which this keeps them from
	// being written too.
	"**/.claude/**", "**/.claude.json*", "**/claude_desktop_config.json", "**/mcp.json", "**/.mcp.json",
	"**/mcp_config.json", "**/mcp-config.json", "**/cline_mcp_settings.json", "**/.config/anthropic/**",
	"**/appdata/roaming/anthropic/**", "**/.codex/**", "**/.gemini/**",
	// The settings that hold Zed's, Continue's, OpenCode's and Goose's MCP
	// server lists, with the environment each server gets: Zed's
	// settings.json in a project and for the user (%APPDATA%\Zed on
	// Windows), Continue's directories, OpenCode's opencode.json wherever it
	// is and its configuration directory, and Goose's (%APPDATA%\Block\goose
	// on Windows).
	"**/.zed/settings.json", "**/.config/zed/settings.json", "**/appdata/roaming/zed/settings.json", "**/.continue/**",
	"**/opencode.json", "**/opencode.jsonc", "**/.config/opencode/**", "**/.config/goose/**",
	"**/appdata/roaming/block/goose/**",
	// Crush's crush.json (in a project, ~/.config/crush, %LOCALAPPDATA%\crush)
	// and Qwen Code's .qwen directories, which hold MCP server lists too.
	"**/crush.json", "**/.crush.json", "**/.config/crush/**", "**/appdata/local/crush/**", "**/.qwen/**",
}

// noWritePaths are never writable, whatever a profile allows, though they
// stay readable where a profile lets the model read: the places where a file
// runs code or grants access later, at boot, at login, on a schedule or when
// a common command runs (persistence points). They match as secretPaths do.
// The list is best effort: it names the common places on Linux, macOS and
// Windows, not every one, so keep write_paths narrow.
var noWritePaths = []string{
	// Accounts, sign-in and privilege.
	"/etc/passwd", "/etc/group", "/etc/pam.conf", "/etc/pam.d/**", "/etc/security/**", "/etc/sudo.conf",
	"/etc/doas.conf", "/usr/local/etc/doas.conf", "/etc/polkit-1/**", "/etc/ssh/**", "**/*authorized_keys*",
	// Libraries every program loads, and kernel and device hooks.
	"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d/**", "/etc/modprobe.d/**", "/etc/sysctl.conf",
	"/etc/sysctl.d/**", "/etc/udev/**", "/lib/udev/**", "/usr/lib/udev/**",
	// Scheduled jobs.
	"/etc/cron*", "/etc/cron*/**", "/etc/anacrontab", "/var/spool/cron/**", "/var/spool/at/**", "/var/at/**",
	"/usr/lib/cron/**", "/etc/periodic/**", "/etc/logrotate.conf", "/etc/logrotate.d/**",
	// Services, boot, and scripts run on system events.
	"/etc/systemd/**", "/lib/systemd/**", "/usr/lib/systemd/**", "/usr/local/lib/systemd/**", "/run/systemd/**",
	"**/.config/systemd/**", "**/.local/share/systemd/**", "/etc/init.d/**", "/etc/init/**", "/etc/rc.local",
	"/etc/rc*.d/**", "/etc/rc.d/**", "/etc/rc.conf", "/etc/inittab", "/etc/apt/apt.conf", "/etc/apt/apt.conf.d/**",
	"/etc/NetworkManager/dispatcher.d/**", "/etc/dhcp/dhclient*hooks.d/**", "/etc/update-motd.d/**",
	"/etc/kernel/**", "/Library/LaunchDaemons/**", "**/Library/LaunchAgents/**", "/Library/StartupItems/**",
	// Login shells and desktop sessions, and the user's own commands.
	"/etc/profile", "/etc/profile.d/**", "/etc/environment", "/etc/environment.d/**", "/etc/bash.bashrc",
	"/etc/bashrc", "/etc/bash_completion.d/**", "/etc/zsh/**", "/etc/zshenv", "/etc/zprofile", "/etc/zshrc",
	"/etc/zlogin", "/etc/csh.cshrc", "/etc/csh.login", "/etc/paths", "/etc/paths.d/**", "/etc/X11/Xsession.d/**",
	"/etc/X11/xinit/**", "/etc/xdg/autostart/**",
	"**/.bashrc", "**/.bash_profile", "**/.bash_login", "**/.bash_logout", "**/.bash_aliases", "**/.profile",
	"**/.zshrc", "**/.zprofile", "**/.zshenv", "**/.zlogin", "**/.zlogout", "**/.cshrc", "**/.tcshrc",
	"**/.login", "**/.kshrc", "**/.config/fish/**", "**/.config/environment.d/**", "**/.config/autostart/**",
	"**/.xprofile", "**/.xinitrc", "**/.xsession", "**/.xsessionrc", "**/.local/bin/**",
	"**/.local/share/applications/**", "**/.config/plasma-workspace/env/**", "**/.config/plasma-workspace/shutdown/**",
	"**/.oh-my-zsh/**", "**/.p10k.zsh", "**/.config/starship.toml",
	// Directories on PATH, where a new file shadows a command (~/bin is put
	// on PATH by the same Debian and Fedora lines as ~/.local/bin), and the
	// files Python runs at every start.
	"/usr/local/bin/**", "/usr/local/sbin/**", "/usr/bin/**", "/usr/sbin/**", "/bin/**", "/sbin/**",
	"/opt/homebrew/bin/**", "/opt/homebrew/sbin/**", "/home/*/bin/**", "/var/home/*/bin/**", "/root/bin/**",
	"/Users/*/bin/**", "**/.cargo/bin/**", "**/site-packages/*.pth", "**/dist-packages/*.pth", "**/sitecustomize.py",
	"**/usercustomize.py",
	// Editors, terminal multiplexers and build tools run these when they
	// start; mail delivery runs a "|command" in .forward.
	"**/.vimrc", "**/.gvimrc", "**/.exrc", "**/.vim/**", "**/.config/nvim/**", "**/.emacs", "**/.emacs.d/**",
	"**/.config/emacs/**", "**/.tmux.conf", "**/.config/tmux/**", "**/.screenrc", "**/.gradle/init.d/**",
	"**/.gradle/init.gradle", "**/.gradle/init.gradle.kts", "**/.cargo/config", "**/.cargo/config.toml", "**/.forward",
	"**/.procmailrc",
	// Commands git runs: a repository's .git (a directory, or a file naming
	// one elsewhere) and everything in it, since git takes its config and
	// hooks from where those files say (a gitdir file, commondir); in bare
	// repositories their config, hooks and commondir; included config files,
	// the directories core.hooksPath commonly names, and submodules' URLs.
	// The same for Mercurial (.hg/hgrc runs hooks and extensions), Jujutsu
	// and Sapling. And a file named HEAD anywhere: with objects/ and refs/
	// beside it, git takes its directory for a bare repository and runs what
	// the config there says, in any directory a shell's prompt or an editor
	// runs git from (safe.bareRepository lets it by default).
	"**/.git", "**/.git/**", "**/*.git/hooks/**", "**/*.git/config", "**/commondir", "**/.gitmodules", "**/head",
	"**/.husky/**", "**/.githooks/**", "**/.gitconfig*", "**/.config/git/**", "**/etc/gitconfig",
	"**/.hg", "**/.hg/**", "**/.jj/**", "**/.sl/**",
	// Project files that run code at a tool's next run: Yarn's yarn-path and
	// plugins, pnpm's and Bun's hooks and preloads, pre-commit's hooks, the
	// Gradle and Maven wrappers and Maven's extensions, dev containers'
	// commands, JetBrains IDEs' run configurations and startup tasks, the
	// URL bazelisk runs Bazel from, and ripgrep's --pre where
	// RIPGREP_CONFIG_PATH names the file. The list is best effort: what a
	// project's tools run is open-ended.
	"**/.yarnrc", "**/.yarn/**", "**/.pnpmfile.cjs", "**/.pnpmfile.mjs", "**/bunfig.toml", "**/.bunfig.toml",
	"**/.pre-commit-config.yaml", "**/.pre-commit-config.yml", "**/gradle/wrapper/**", "**/.mvn/**",
	"**/.devcontainer/**", "**/.devcontainer.json", "**/.idea/**", "**/.bazeliskrc", "**/.ripgreprc",
	// Hooks of package managers, network setup, the boot loader and other
	// system tools, and user-namespace grants.
	"/etc/dpkg/dpkg.cfg", "/etc/dpkg/dpkg.cfg.d/**", "/etc/needrestart/**", "/etc/pacman.conf", "/etc/pacman.d/hooks/**",
	"/usr/share/libalpm/hooks/**", "/etc/apk/commit_hooks.d/**", "/etc/network/**", "/etc/grub.d/**", "/etc/default/grub",
	"/etc/default/grub.d/**", "/boot/**", "/etc/tmpfiles.d/**", "/usr/lib/tmpfiles.d/**", "/run/tmpfiles.d/**",
	"/etc/subuid", "/etc/subgid", "/usr/share/polkit-1/**", "/etc/xdg/systemd/**", "/etc/rsyslog.conf",
	"/etc/rsyslog.d/**", "/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local", "/etc/periodic.conf",
	// Windows: Startup folders, scheduled tasks, Group Policy scripts and
	// PowerShell profiles, the per-user WindowsApps directory on every
	// user's PATH, Office's startup folders and global templates, and the
	// module directories PowerShell loads modules from by name.
	"**/start menu/programs/startup/**", "/*:/windows/system32/tasks/**", "/*:/windows/tasks/**",
	"/*:/windows/system32/grouppolicy/**", "/*:/windows/system32/grouppolicyusers/**", "**/*profile.ps1",
	"**/appdata/local/microsoft/windowsapps/**", "**/xlstart/**", "**/microsoft/word/startup/**",
	"**/microsoft office/root/office*/startup/**", "**/microsoft office/office*/startup/**",
	"**/microsoft/templates/normal.dotm", "**/microsoft/templates/normalemail.dotm",
	"**/windowspowershell/modules/**", "**/windowspowershell/v1.0/modules/**", "**/powershell/modules/**",
	"**/powershell/*/modules/**",
	// Windows: the per-user program folders, whose programs run as the user
	// and many of which are on the user's PATH: %LocalAppData%\Programs,
	// where per-user installers put programs (VS Code, Python, Cursor);
	// Claude's own folder, and those of other Squirrel installers, which keep
	// each version in an app-<version> folder beside the Update.exe that
	// runs at sign-in (Discord, Slack, GitHub Desktop); WinGet's links and
	// portable packages; and the Scripts folders of Python's user installs.
	"**/appdata/local/programs/**", "**/appdata/local/anthropicclaude/**", "**/appdata/local/*/app-*/**",
	"**/appdata/local/*/update.exe", "**/appdata/local/microsoft/winget/links/**",
	"**/appdata/local/microsoft/winget/packages/**", "**/appdata/roaming/python/*/scripts/**",
	// Startup files: bash's drop-in directory and completions, the login
	// scripts of KDE Plasma 5, and what gdb, psql, sqlite3, irb, IPython,
	// Jupyter, Maven, i3, sway and WezTerm run when they start; Kerberos's
	// list of who may log in as the user; the directories on PATH that
	// language tools and package managers add (Go's, Linuxbrew's, npm's,
	// Yarn's, Deno's, Bun's, Scoop's, .NET tools'); and the files Outlook and
	// Windows Terminal run code from.
	"**/.bashrc.d/**", "**/.bash_completion", "**/.bash_completion.d/**", "**/.local/share/bash-completion/**",
	"/etc/bash_completion", "/usr/share/bash-completion/**", "/usr/local/share/bash-completion/**",
	"**/.config/autostart-scripts/**", "**/.gdbinit", "**/.gdbinit.d/**", "**/.config/gdb/**", "**/.psqlrc*",
	"**/.sqliterc", "**/.irbrc", "**/.pryrc", "**/.config/irb/**", "**/.ipython/**", "**/.jupyter/**",
	"**/.mavenrc", "/etc/mavenrc", "**/.config/i3/**", "**/.i3/**", "**/.config/sway/**", "**/.wezterm.lua",
	"**/.config/wezterm/**", "**/.k5login", "**/.k5users",
	"**/go/bin/**", "**/.linuxbrew/bin/**", "**/.linuxbrew/sbin/**", "**/.npm-global/bin/**",
	"**/.deno/bin/**", "**/.bun/bin/**", "**/appdata/roaming/npm/**", "**/scoop/shims/**", "**/scoop/apps/**",
	"**/.dotnet/tools/**", "**/microsoft/outlook/vbaproject.otm", "**/microsoft.windowsterminal*/localstate/settings.json",
	// System hooks: kubelet's static pods (it runs any pod put there), PAM
	// modules (sshd, login and sudo load them as root), the NSS modules every
	// user lookup loads, D-Bus services (started as root on demand) and
	// policy, the initramfs, acpid's event actions, display managers' login
	// scripts, and Docker's daemon settings, which can open a root-equivalent
	// API.
	"/etc/kubernetes/manifests/**", "/lib/security/**", "/lib64/security/**", "/lib/*/security/**",
	"/usr/lib/security/**", "/usr/lib64/security/**", "/usr/lib/*/security/**", "/usr/lib/pam/**",
	"/etc/nsswitch.conf", "/etc/dbus-1/**", "/usr/share/dbus-1/**", "/usr/local/share/dbus-1/**",
	"**/.local/share/dbus-1/**", "/etc/initramfs-tools/**", "/usr/share/initramfs-tools/**", "/etc/dracut.conf",
	"/etc/dracut.conf.d/**", "/usr/lib/dracut/**", "/etc/mkinitcpio.conf", "/etc/mkinitcpio.d/**", "/etc/initcpio/**",
	"/usr/lib/initcpio/**", "/etc/acpi/**", "/etc/lightdm/**", "/etc/gdm/**", "/etc/gdm3/**", "/etc/sddm.conf",
	"/etc/sddm.conf.d/**", "/usr/share/sddm/scripts/**", "/etc/docker/daemon.json", "**/.config/docker/daemon.json",
	// Windows: the files directly in C:\Windows, System32 and the other
	// system folders on every user's PATH, where a program or DLL shadows or
	// joins the system's (their subfolders, such as Temp or drivers\etc, are
	// left to the profile), and PowerShell 7's folder, as /usr/bin is.
	"/*:/windows/*", "/*:/windows/system32/*", "/*:/windows/syswow64/*", "/*:/windows/system32/wbem/*",
	"/*:/windows/system32/windowspowershell/v1.0/*", "/*:/windows/system32/openssh/*", "/*:/program files/powershell/**",
	// Apache's and nginx's configuration: any file they read can run a
	// command when the server starts (a piped log, CustomLog "|cmd") or load
	// a module (LoadModule, load_module).
	"/etc/apache2/**", "/etc/httpd/**", "/usr/local/etc/apache2*/**", "/usr/local/etc/httpd/**",
	"/opt/homebrew/etc/httpd/**", "/etc/nginx/**", "/usr/local/etc/nginx/**", "/opt/homebrew/etc/nginx/**",
	"/usr/local/nginx/conf/**",
	// MCP clients, AI coding tools and editors run code their configuration
	// names, when they start or a folder is opened: MCP servers, hooks,
	// tasks, extensions and plugins; and they load instruction files into
	// every session (CLAUDE.md, AGENTS.md, GEMINI.md, rules files), which
	// steer what the model runs. Claude Code's managed settings and Claude
	// Desktop's extensions; Cursor, VS Code and its forks, and the servers
	// they install on hosts they reach; Windsurf, Zed, Continue, Copilot CLI,
	// Amazon Q, Goose and OpenCode; the system settings and hooks Gemini
	// CLI, Cursor and Codex take for every user; and the instruction files
	// of Codex (AGENTS.override.md), Copilot, Goose and Zed. Their files that
	// hold logins are in secretPaths.
	"**/claude.md", "**/claude.local.md", "**/agents.md", "**/gemini.md", "**/.cursorrules", "**/.windsurfrules",
	"**/.clinerules", "**/.clinerules/**", "**/agents.override.md", "**/.github/copilot-instructions.md",
	"**/.github/instructions/**", "**/.goosehints", "**/.rules", "/etc/gemini-cli/**",
	"/Library/Application Support/GeminiCli/**", "/*:/programdata/gemini-cli/**", "/etc/cursor/**",
	"/*:/programdata/cursor/**", "/etc/codex/**", "**/appdata/roaming/zed/**",
	"/etc/claude-code/**", "/Library/Application Support/ClaudeCode/**",
	"/*:/program files/claudecode/**", "**/.config/claude/**", "**/Library/Application Support/Claude/**",
	"**/roaming/claude/**", "**/.cursor/**", "**/.vscode/**", "**/.vscode-insiders/**", "**/.vscode-oss/**",
	"**/.windsurf/**", "**/.codeium/**", "**/.vscode-server/**", "**/.vscode-server-insiders/**",
	"**/.vscodium-server/**", "**/.cursor-server/**", "**/.windsurf-server/**",
	"**/.config/code/**", "**/.config/code - insiders/**", "**/.config/vscodium/**", "**/.config/cursor/**",
	"**/.config/windsurf/**", "**/Library/Application Support/Code/**",
	"**/Library/Application Support/Code - Insiders/**", "**/Library/Application Support/VSCodium/**",
	"**/Library/Application Support/Cursor/**", "**/Library/Application Support/Windsurf/**",
	"**/appdata/roaming/code/**", "**/appdata/roaming/code - insiders/**", "**/appdata/roaming/vscodium/**",
	"**/appdata/roaming/cursor/**", "**/appdata/roaming/windsurf/**", "**/.zed/**", "**/.config/zed/**",
	"**/.copilot/**", "**/.amazonq/**", "**/.opencode/**",
}

// RunDecision judges a command. With shell set, argv holds exactly one
// command line for sh -c or cmd /c. The reason explains a denial, or why a
// human is asked; it is written for the model so it can adapt.
func (p *Policy) RunDecision(argv []string, shell bool) (Decision, string) {
	if len(argv) == 0 || argv[0] == "" {
		return Deny, "argv is empty"
	}
	if shell {
		switch {
		case !p.allowShell:
			return Deny, fmt.Sprintf("shell mode is not allowed in profile %s; pass argv without shell, allowed: %s", p.Profile, p.AllowedSummary())
		case len(argv) != 1:
			return Deny, "shell mode takes exactly one argv element: the command line"
		case p.confirm["run"] || p.confirm["run:shell"]:
			return Confirm, fmt.Sprintf("shell mode needs a human's approval in profile %s", p.Profile)
		}
		return Allow, ""
	}
	if why := commandNameProblem(argv[0]); why != "" {
		return Deny, fmt.Sprintf("argv[0] must be a bare command name in profile %s, not %s; allowed: %s", p.Profile, why, p.AllowedSummary())
	}
	if !p.allowWrappers && isWrapper(argv[0]) && !slices.ContainsFunc(p.allow, func(pat []string) bool {
		return literalPattern(pat) && slices.Equal(pat, argv)
	}) {
		return Deny, fmt.Sprintf("%s can run arbitrary commands (shell, interpreter or wrapper) and is not allowed in profile %s; allowed: %s", quote(argv[0]), p.Profile, p.AllowedSummary())
	}
	for _, pat := range p.allow {
		if matchArgv(pat, argv) {
			if p.confirm["run"] {
				return Confirm, fmt.Sprintf("every command needs a human's approval in profile %s", p.Profile)
			}
			return Allow, ""
		}
	}
	// The command is rendered as the confirmation form shows it, so the
	// reason, which the form shows too, carries nothing hidden.
	if p.confirmUnlisted {
		return Confirm, fmt.Sprintf("the command %s is not in the %s allowlist, so a human must approve it", showArgv(redactAll(argv)), p.Profile)
	}
	return Deny, fmt.Sprintf("the command %s is not in the %s allowlist; allowed: %s", showArgv(redactAll(argv)), p.Profile, p.AllowedSummary())
}

// StdinProblem says why argv may not be given standard input, or "". A
// shell, interpreter or wrapper runs what it reads, so one that only a
// pattern with no slot lets run (see RunDecision) takes no input: ["sh"]
// would otherwise run any command it is fed.
func (p *Policy) StdinProblem(argv []string, shell bool) string {
	if shell || p.allowWrappers || len(argv) == 0 || !isWrapper(argv[0]) {
		return ""
	}
	return fmt.Sprintf("%s can run what it reads, and profile %s lets it run only as the fixed command line a pattern gives, so it takes no stdin; set run.allow_wrappers to allow that deliberately", quote(argv[0]), p.Profile)
}

// Confirms reports whether tool needs a human's approval in this profile.
func (p *Policy) Confirms(tool string) bool { return p.confirm[tool] }

// PTYAllowed reports whether the profile lets the model open terminals.
func (p *Policy) PTYAllowed() bool { return p.allowPTY }

// PTYLimits returns how many terminals may be open on a target at once and
// how long one may sit unused before it is closed.
func (p *Policy) PTYLimits() (int, time.Duration) {
	n, idle := defaultPTYsPerTarget, defaultPTYIdle
	if p.ptyMax > 0 {
		n = p.ptyMax
	}
	if p.ptyIdle > 0 {
		idle = p.ptyIdle
	}
	return n, idle
}

// PTYOpenDecision judges opening a terminal.
func (p *Policy) PTYOpenDecision() (Decision, string) {
	switch {
	case !p.allowPTY:
		return Deny, fmt.Sprintf("profile %s does not allow interactive terminals; use run instead", p.Profile)
	case p.confirm["pty_open"]:
		return Confirm, fmt.Sprintf("opening a terminal needs a human's approval in profile %s", p.Profile)
	}
	return Allow, ""
}

// PTYInputDecision judges typing into a terminal. Anything typed may run as a
// command, so it needs approval exactly when shell commands do.
func (p *Policy) PTYInputDecision() (Decision, string) {
	switch {
	case !p.allowPTY:
		return Deny, fmt.Sprintf("profile %s does not allow interactive terminals", p.Profile)
	case p.confirm["run"] || p.confirm["run:shell"]:
		return Confirm, fmt.Sprintf("typing into a terminal needs a human's approval in profile %s, as shell commands do", p.Profile)
	}
	return Allow, ""
}

// ConfirmActions lists the actions that need approval, for agent_info.
func (p *Policy) ConfirmActions() []string { return nonNil(slices.Sorted(maps.Keys(p.confirm))) }

// ConfirmsUnlisted reports whether unlisted commands may run after approval.
func (p *Policy) ConfirmsUnlisted() bool { return p.confirmUnlisted }

// CheckRead reports whether read_file or download may open raw, returning
// the normalized path to send to the agent. The agent resolves symlinks, which
// this check cannot see: a link under an allowed directory still reads its
// target, unless that is a secret path (see CheckReal), or lies outside every
// path the profile may read and is not readable by every user (see
// ReadCheck). A hard link is not caught at all: it is the file itself under a
// second name, with no other path to check, so a hard link to a secret file
// inside an allowed tree reads it. Only someone who may already write the
// secret can make one where Linux's fs.protected_hardlinks is on, as most
// distributions ship it.
func (p *Policy) CheckRead(raw string) (string, bool, string) {
	key, agentPath, why := remotePath(raw)
	if why != "" {
		return raw, false, why
	}
	if pat := matchSecret(key); pat != "" {
		return agentPath, false, fmt.Sprintf("%s matches the secret-path rule %q and is never readable", agentPath, pat)
	}
	if matchAny(p.readAllow, key) {
		return agentPath, true, ""
	}
	return agentPath, false, fmt.Sprintf("%s is outside the paths profile %s may read: %s", agentPath, p.Profile, strings.Join(p.readAllow, ", "))
}

// CheckReal vets the path the agent reports a read or write really reaches,
// links resolved, against the secret-path rules, which no link may get
// around. The allowlist is not applied again: links inside allowed trees,
// such as /etc/resolv.conf, commonly point elsewhere. An agent that reports no
// path is refused, since nothing could be checked.
// The path comes from the agent, so messages show it escaped, as the
// confirmation form would: nothing invisible reaches the model through them.
func (p *Policy) CheckReal(real string) error {
	if real == "" {
		return errors.New("denied: the agent did not report where the path really leads, so the secret-path rules cannot be checked there; run ternd of the same release as this tern on that host")
	}
	key, agentPath, why := remotePath(real)
	if why != "" {
		return fmt.Errorf("the agent resolved the path to %s, which is refused: %s", quote(real), why)
	}
	if pat := matchSecret(key); pat != "" {
		return fmt.Errorf("denied: the path leads through a link to %s, which matches the secret-path rule %q", show(agentPath), pat)
	}
	return nil
}

// CheckRealWrite is CheckReal for a write, which must not reach a persistence
// point through a link either (see noWritePaths).
func (p *Policy) CheckRealWrite(real string) error {
	if err := p.CheckReal(real); err != nil {
		return err
	}
	key, agentPath, _ := remotePath(real) // CheckReal accepted it
	if pat := matchRule(noWritePaths, key); pat != "" {
		return fmt.Errorf("denied: the path leads through a link to %s, which matches the persistence-point rule %q and is never writable", show(agentPath), pat)
	}
	return nil
}

// ReadCheck returns the check read_file and download run on the agent's reply
// for agentPath, before any content moves: CheckReal on the path the file
// really has, then whether every user may read the file, which takes its own
// others-read bit and others-search on every directory above it (dirsOpen):
// a 0644 file in a 0700 directory is private. A path the profile names
// itself, where the file really is too, is read whatever its mode. Otherwise
// a file that not every user may read is refused under worldReadableRead,
// judged as asked for and also where a link leads, so a link from a tree the
// built-in rules read whatever the mode (/var/log) into /etc reaches only
// what /etc itself would show; and it is refused where a link leads out of
// every path the profile may read, so a link planted in a log directory
// reaches nothing private elsewhere either. A Windows agent reports every
// file as readable by all.
func (p *Policy) ReadCheck(agentPath string) func(real string, perm os.FileMode, dirsOpen bool) error {
	return func(real string, perm os.FileMode, dirsOpen bool) error {
		if err := p.CheckReal(real); err != nil {
			return err
		}
		key, _, why := remotePath(agentPath)
		if why != "" {
			return nil
		}
		realKey, _, _ := remotePath(real) // CheckReal accepted it
		if matchAny(p.userRead, key) && matchReal(p.userRead, realKey) {
			return nil
		}
		inside := matchReal(p.readAllow, realKey)
		if inside && !matchAny(p.worldOnly, key) && matchRule(p.worldOnly, realKey) == "" {
			return nil
		}
		rule := fmt.Sprintf("profile %s reads such files there only where it names them itself, since they commonly hold credentials", p.Profile)
		if !inside {
			rule = fmt.Sprintf("it is reached through a link that leads out of the paths profile %s may read, and such a link reaches only files every user may read", p.Profile)
		}
		switch {
		case perm&0o004 == 0:
			return fmt.Errorf("denied: %s is not readable by every user (mode %04o): %s", show(agentPath), perm, rule)
		case !dirsOpen:
			return fmt.Errorf("denied: %s is not readable by every user: its mode is %04o, but a directory above it keeps other users out; %s", show(agentPath), perm, rule)
		}
		return nil
	}
}

// CheckWrite reports whether write_file or upload may write raw, returning
// the normalized path to send to the agent.
func (p *Policy) CheckWrite(raw string) (string, bool, string) {
	key, agentPath, why := remotePath(raw)
	if why != "" {
		return raw, false, why
	}
	if pat := matchSecret(key); pat != "" {
		return agentPath, false, fmt.Sprintf("%s matches the secret-path rule %q and is never writable", agentPath, pat)
	}
	if pat := matchRule(noWritePaths, key); pat != "" {
		return agentPath, false, fmt.Sprintf("%s matches the persistence-point rule %q: a file there can run code or grant access later, so it is never writable", agentPath, pat)
	}
	if len(p.writeAllow) == 0 {
		return agentPath, false, fmt.Sprintf("profile %s does not allow writing files", p.Profile)
	}
	if matchAny(p.writeAllow, key) {
		return agentPath, true, ""
	}
	return agentPath, false, fmt.Sprintf("%s is outside the paths profile %s may write: %s", agentPath, p.Profile, strings.Join(p.writeAllow, ", "))
}

// remotePath validates a path on the agent. It returns the key rules match
// against, the path to send, or why the path is refused. Unix paths are
// cleaned lexically, so ".." cannot walk around a rule. Windows drive paths
// are cleaned below the drive root, use forward slashes, and get a lowercase
// key, because Windows compares paths without case.
func remotePath(raw string) (key, agentPath, why string) {
	switch {
	case raw == "" || strings.ContainsRune(raw, 0):
		return "", "", "path is empty or contains a NUL byte"
	case strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, "//"):
		return "", "", "UNC and device paths are not supported"
	case strings.HasPrefix(raw, "/"):
		// A Windows agent treats \ as a separator too, so "/etc/..\..\x"
		// would walk out of /etc after the rules saw a path inside it.
		if strings.ContainsRune(raw, '\\') {
			return "", "", `a /slash path must not contain \; write Windows paths as C:\dir\file`
		}
		p := path.Clean(raw)
		if why := windowsAlias(p); why != "" {
			return "", "", why
		}
		if why := dotAlias(p); why != "" {
			return "", "", why
		}
		if first, _, _ := strings.Cut(p[1:], "/"); fold(first) == ".vol" {
			// macOS opens /.vol/<device>/<inode> by inode number, a name
			// no rule can see through.
			return "", "", "/.vol paths open a file by its inode number on macOS, which the path rules cannot see; use the file's name"
		}
		return p, p, ""
	case isDrivePath(raw):
		if strings.Count(raw, ":") > 1 {
			return "", "", "alternate data streams (a second ':') are not supported"
		}
		s := strings.ReplaceAll(raw, `\`, "/")
		rest := path.Clean("/" + s[3:]) // s[:2] is the drive, s[2] a separator
		if dev := windowsDevice(path.Base(rest)); dev != "" {
			return "", "", fmt.Sprintf("%s is a Windows device name, not a file", dev)
		}
		if why := windowsAlias(rest); why != "" {
			return "", "", why
		}
		if why := dotAlias(rest); why != "" {
			return "", "", why
		}
		agentPath = strings.ToUpper(s[:2]) + rest
		return "/" + strings.ToLower(agentPath), agentPath, ""
	}
	return "", "", `path must be absolute: /unix/path or C:\windows\path`
}

// windowsAlias refuses names a Windows agent would open as a different name
// than the rules see: trailing dots and spaces (Windows drops them, so
// "srv.key." opens srv.key), 8.3 short names (SSH~1 opens .ssh) and the
// unnamed data stream ("srv.key::$DATA"). Rules match the long, exact name,
// so an alias would walk around a secret-path rule. Slash paths are checked
// too, because a Windows agent opens /Users/x as C:\Users\x.
func windowsAlias(p string) string {
	for _, seg := range strings.Split(p, "/") {
		switch {
		case seg == "":
		case strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " "):
			return fmt.Sprintf("%s ends with a dot or space, which Windows drops; use the exact name", quote(seg))
		case isShortName(seg):
			return fmt.Sprintf("%s looks like a Windows 8.3 short name; use the long name", quote(seg))
		case strings.Contains(seg, "::") || strings.Contains(seg, ":$") || strings.HasSuffix(seg, ":"):
			return fmt.Sprintf("%s names a Windows data stream, which is not supported", quote(seg))
		}
	}
	return ""
}

// dotAlias refuses a name a case-insensitive file system may take for "." or
// "..": Linux casefold ignores default-ignorable characters, so it can read
// "..\u200d" as "..", which path.Clean does not, and the rules would see a
// path inside an allowed directory that leaves it.
func dotAlias(p string) string {
	for _, seg := range strings.Split(p, "/") {
		if f := fold(seg); f != seg && (f == "." || f == "..") {
			return fmt.Sprintf("%s reads as %q on a case-insensitive file system; use the plain name", quote(seg), f)
		}
	}
	return ""
}

// isShortName reports an 8.3 short name: at most eight characters ending in
// "~" and digits, and an extension of at most three, as in PROGRA~1 or
// API_TO~1.TXT. Longer names with a "~", such as Debian's
// pkg_1.0~rc1.1_amd64.deb, are not short names.
func isShortName(seg string) bool {
	base, ext, _ := strings.Cut(seg, ".")
	i := strings.LastIndexByte(base, '~')
	if len(base) > 8 || len(ext) > 3 || strings.Contains(ext, ".") || i < 1 || i == len(base)-1 {
		return false
	}
	return strings.Trim(base[i+1:], "0123456789") == ""
}

func isDrivePath(s string) bool {
	return len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') &&
		(s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z')
}

// windowsDevice reports a reserved Windows device name such as CON or NUL,
// which name devices in every directory and would block or misbehave if read
// or written as files.
func windowsDevice(base string) string {
	stem, _, _ := strings.Cut(base, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return stem
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9' {
		return stem
	}
	return ""
}

func isWindowsKey(key string) bool { return len(key) >= 3 && key[0] == '/' && key[2] == ':' }

// matchSecret returns the secret-path rule key matches.
func matchSecret(key string) string { return matchRule(secretPaths, key) }

// matchRule returns the rule in rules that key matches, ignoring case, also
// once folded (see fold). A slash path is also matched as if on a drive,
// because a Windows agent opens /Windows/System32/config/SAM on its current
// drive, and under the names macOS gives the same file (see macNames).
func matchRule(rules []string, key string) string {
	keys := ruleKeys(key)
	for _, pat := range rules {
		if ruleMatches(pat, keys) {
			return pat
		}
	}
	return ""
}

// ruleKeys returns the spellings of key that matchRule tries.
func ruleKeys(key string) []string {
	var keys []string
	add := func(k string) {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	for _, k := range []string{strings.ToLower(key), fold(key)} {
		add(k)
		if isWindowsKey(k) {
			continue
		}
		add("/_:" + k)
		for _, n := range macNames(k) {
			add(n)
		}
	}
	return keys
}

// ruleMatches reports whether the rule pat matches one of keys, from ruleKeys.
func ruleMatches(pat string, keys []string) bool {
	lp := strings.ToLower(pat)
	return slices.ContainsFunc(keys, func(k string) bool { return matchPath(lp, k) })
}

// macDataVolume is where macOS mounts its writable Data volume, lowercase.
// It is firmlinked into the root: /System/Volumes/Data/Library is /Library,
// and so are /Users, /usr/local, /private, /opt and the other firmlinks. A
// firmlink is not a symbolic link, so an agent's resolved path keeps either
// spelling.
const macDataVolume = "/system/volumes/data"

// macNames returns the other names macOS gives the file at k, a slash path:
// without the Data volume's mount point, and without /private, since /etc,
// /var and /tmp are links into /private, which is where an agent resolves
// them. Rules anchored at /etc or /Library thus match either way. The mount
// point and /private are recognized in any case, as APFS opens them, and the
// rest of k keeps its own.
func macNames(k string) []string {
	var out []string
	for {
		rest, ok := cutPrefixFold(k, macDataVolume)
		if !ok || rest != "" && rest[0] != '/' {
			break
		}
		if k = rest; k == "" {
			k = "/"
		}
		out = append(out, k)
	}
	for _, d := range []string{"/private/etc", "/private/var", "/private/tmp"} {
		if rest, ok := cutPrefixFold(k, d); ok && (rest == "" || rest[0] == '/') {
			out = append(out, k[len("/private"):])
		}
	}
	return out
}

// cutPrefixFold is strings.CutPrefix with prefix, which is lowercase ASCII,
// matched without regard to case.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// matchReal is matchAny for real, the key of a path an agent reported for a
// file it opened, under any name macOS gives the same file: an agent there
// reports /var/log/system.log as /private/var/log/system.log.
func matchReal(pats []string, real string) bool {
	if matchAny(pats, real) {
		return true
	}
	return !isWindowsKey(real) && slices.ContainsFunc(macNames(real), func(n string) bool { return matchAny(pats, n) })
}

// foldASCII maps every character that Unicode case folding or canonical
// decomposition turns into ASCII, as of Unicode 17 (the C and F mappings of
// CaseFolding.txt, and the decompositions in UnicodeData.txt): the long s is
// s, the sharp s, small and capital, is ss, the Kelvin sign is k, the
// ligatures U+FB00 to U+FB06 are ff, fi, fl, ffi, ffl, st and st, and the
// Greek question mark and varia decompose to ";" and "`". strings.ToLower
// already lowers the Kelvin sign, and the capital sharp s to the small one.
var foldASCII = map[rune]string{
	'\u00df': "ss", '\u017f': "s", '\u1e9e': "ss", '\u212a': "k",
	'\ufb00': "ff", '\ufb01': "fi", '\ufb02': "fl", '\ufb03': "ffi", '\ufb04': "ffl", '\ufb05': "st", '\ufb06': "st",
	'\u037e': ";", '\u1fef': "`",
}

// fold renders s as a case-insensitive file system compares names, as far as
// the rules can tell: Linux casefold directories (ext4, f2fs and tmpfs with
// the +F attribute) and APFS fold Unicode case fully, and Linux also ignores
// default-ignorable characters such as zero-width joiners and variation
// selectors. There ".\u017fsh", ".\u00dfh" and ".s\u200dsh" all open .ssh, so
// the rules that must never be walked around match the folded form too.
func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if a, ok := foldASCII[r]; ok {
			b.WriteString(a)
		} else if !invisible(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// matchAny reports whether key matches one of pats: exactly on Unix, without
// case on Windows.
func matchAny(pats []string, key string) bool {
	win := isWindowsKey(key)
	for _, pat := range pats {
		if win {
			pat = strings.ToLower(pat)
		}
		if matchPath(pat, key) {
			return true
		}
	}
	return false
}

// AllowedSummary renders the allowlist for messages.
func (p *Policy) AllowedSummary() string {
	return strings.Join(p.AllowedCommands(), ", ")
}

// AllowedCommands renders each allowed pattern, with <arg> for "*" and
// <args...> for "**".
func (p *Policy) AllowedCommands() []string {
	out := make([]string, 0, len(p.allow))
	for _, pat := range p.allow {
		toks := make([]string, len(pat))
		for i, t := range pat {
			switch t {
			case "*":
				toks[i] = "<arg>"
			case numTok:
				toks[i] = "<number>"
			case nameTok:
				toks[i] = "<name>"
			case unitTok:
				toks[i] = "<unit>"
			case "**":
				toks[i] = "<args...>"
			default:
				toks[i] = t
			}
		}
		out = append(out, strings.Join(toks, " "))
	}
	return out
}

// AllowedReadPaths and AllowedWritePaths list the path patterns.
func (p *Policy) AllowedReadPaths() []string  { return p.readAllow }
func (p *Policy) AllowedWritePaths() []string { return p.writeAllow }

// ShellAllowed reports whether run accepts a shell command line.
func (p *Policy) ShellAllowed() bool { return p.allowShell }

// CanWrite reports whether the profile allows writing any file.
func (p *Policy) CanWrite() bool { return len(p.writeAllow) > 0 }

// RunReadOnly reports whether every command run may execute is one of the
// built-in read-only diagnostics.
func (p *Policy) RunReadOnly() bool { return !p.allowShell && !p.allowWrappers && !p.userRun }

// literalPattern reports whether pat has no slot: every token is matched as
// it is written, so it allows exactly one command line.
func literalPattern(pat []string) bool {
	return !slices.ContainsFunc(pat, func(t string) bool {
		return t == "*" || t == "**" || t == numTok || t == nameTok || t == unitTok
	})
}

func matchArgv(pat, argv []string) bool {
	if n := len(pat); n > 0 && pat[n-1] == "**" {
		if len(argv) < n-1 {
			return false
		}
		return matchTokens(pat[:n-1], argv[:n-1])
	}
	return len(pat) == len(argv) && matchTokens(pat, argv)
}

func matchTokens(pat, argv []string) bool {
	for i, t := range pat {
		a := argv[i]
		switch t {
		case "*":
		case numTok:
			if a == "" || len(a) > 9 || strings.Trim(a, "0123456789") != "" {
				return false
			}
		case nameTok:
			if a == "" || strings.HasPrefix(a, "-") {
				return false
			}
		case unitTok:
			if a == "" || strings.HasPrefix(a, "-") || strings.ContainsAny(a, `*?[]\`) {
				return false
			}
		default:
			if t != a {
				return false
			}
		}
	}
	return true
}

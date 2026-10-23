// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Tool results go into the model's context and so leave the host, to the
// model provider. Redaction removes the secrets that most often show up in
// command output and config files before that happens. It is a safety net, not
// a guarantee: the secret-path rules keep the usual secret files from being
// read at all.
type redaction struct {
	re   *regexp.Regexp
	repl string
	// val, when set, is the submatch that holds the secret value. A value
	// that is a marker, put there by an earlier rule, is left as it is, so
	// API_KEY=sk-... keeps its typed marker and counts once; a value that
	// only begins with one, as when a token-like match took its first part,
	// is replaced whole.
	val int
	// hint holds strings, one of which every match holds, case-folded (see
	// foldCase): text that holds none is not searched, which spares most
	// rules most text.
	hint []string
	// except, when set, matches the lines on which a match that starts the
	// line is left as it is (see keep).
	except *regexp.Regexp
}

// nssLine is an nsswitch.conf passwd line, which names the services that
// look users up (files systemd, sss, ldap, an action such as
// [NOTFOUND=return]), not a password.
var nssLine = regexp.MustCompile(`^[ \t]*passwd(?:_compat)?:[ \t]+` + nssWord + `(?:[ \t]+` + nssWord + `)*[ \t]*\r?$`)

const nssWord = `(?:files|db|dns|nis|nisplus|hesiod|compat|systemd|sss|ldap|winbind|wins|cache|altfiles|extrausers|usrfiles|myhostname|mymachines|resolve|oslogin|kanidm|lmdb|mdns[46]?(?:_minimal)?|\[[^\]\r\n]*\])`

// keep reports whether r leaves m, a match of its pattern in s, as it is:
// its value is a marker an earlier rule put there, perhaps quoted, or the
// match starts a line that r.except matches.
func (r *redaction) keep(s string, m []int) bool {
	if r.val > 0 && m[2*r.val] >= 0 && isMarker(s[m[2*r.val]:m[2*r.val+1]]) {
		return true
	}
	if r.except == nil {
		return false
	}
	lo := m[0]
	for lo > 0 && (s[lo-1] == ' ' || s[lo-1] == '\t') {
		lo--
	}
	if lo > 0 && s[lo-1] != '\n' {
		return false
	}
	hi := len(s)
	if i := strings.IndexByte(s[m[0]:], '\n'); i >= 0 {
		hi = m[0] + i
	}
	return r.except.MatchString(s[lo:hi])
}

// secretWords are the strings one of which every secretName holds.
var secretWords = []string{"pass", "secret", "token", "api", "access", "private", "credential", "pwd", "app"}

// foldCase maps s so that a string a case-insensitive pattern matches holds
// the hints of its rule: every letter that folds to an ASCII letter, as the
// Kelvin sign folds to k and the long s to s, becomes that letter in lower
// case.
func foldCase(s string) string { return strings.ToLower(strings.ToUpper(s)) }

// secretName is a name that says its value is secret, as in env dumps and
// config files (this also covers TERN_TOKEN and friends): one that ends in a
// secret word, or holds one followed by a separator, as SECRET_KEY and
// SECRET_KEY_BASE do, or a *_PWD, *_PASS or APP_KEY. Matched without regard
// to case, it also covers camelCase keys such as dbPassword, apiKey and
// secretKey. A bare PWD or OLDPWD is the working directory, and TOKENIZER,
// "tokens: 3" or "pass: 3" say nothing secret.
const secretName = `[A-Z0-9_.-]*(?:(?:PASSWORDS?|PASSWD|PASSPHRASE|SECRET(?:KEY)?|TOKEN|API[_-]?KEYS?|ACCESS[_-]?KEYS?|PRIVATE[_-]?KEYS?|CREDENTIALS?)|(?:[_.-]PWD|[_.-]PASS|APP[_-]KEY|SSHPASS))(?:[_.-][A-Z0-9_.-]*)?`

// quotedValue is a quoted value, in which a backslash escapes the next
// character, as in JSON.
const quotedValue = `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`

// marker is a [REDACTED ...] marker an earlier rule put in. The value
// patterns take one as a unit, spaces and all, so a value that goes on past
// it is replaced whole.
const marker = `\[REDACTED(?: [A-Z]+)*\]`

// looseValue is an unquoted value, which may hold quoted parts and markers,
// or a quote that is never closed, as a shell or a careless config writes
// one: it ends at a space outside quotes.
const looseValue = `(?:` + marker + `|[^\s"']|"(?:[^"\\\n]|\\.)*"?|'[^'\n]*'?)+`

// flagValue is the value of a command-line option: quoted, or a word that
// does not start with a dash.
const flagValue = `"[^"]*"|'[^']*'|(?:` + marker + `|[^\s"'-])(?:` + marker + `|\S)*`

// word is a value up to the next space, a marker taken whole.
const word = `(?:` + marker + `|\S)+`

// lineValue is an unquoted value of more than one word that runs to the end
// of its line: the value of a name that starts the line in an env dump, an
// INI, .properties or .env file, or cmd's set. Its first character is no
// quote, which makes it a quoted value, nor the > of a => arrow, nor what
// begins a reference or an expression rather than a secret: $ (${VAR},
// $(command), ${{ secrets.X }}) or { (a TOML inline table). It stops before
// a comment, a word starting with #, ; // or /*, and before a lone \ that
// continues a command line.
const lineValue = `(?:` + marker + `|[^\s"'>${])(?:` + marker + `|\S)*(?:[ \t]+(?:(?:` + marker + `|[^\s#;/\\]|/[^\s/*]|\\\S)(?:` + marker + `|\S)*|/))+`

// lineEnd is what may end a lineValue's line after it: a comment and a \
// that continues the line.
const lineEnd = `((?:[ \t]+(?:#|;|//|/\*)[^\r\n]*)?(?:[ \t]+\\)?[ \t]*\r?)$`

// yamlValue is lineValue in YAML, where a # after a space starts a comment,
// and a value that starts with a tag (!secret name), an anchor or an alias
// (*name) or a flow collection ([a, b]) is no plain one.
const yamlValue = `(?:` + marker + `|[^\s"'#${\[&*!])(?:` + marker + `|\S)*(?:[ \t]+(?:` + marker + `|[^\s#\\]|\\\S)(?:` + marker + `|\S)*)+`

// yamlTagged is a YAML value after a tag or an anchor: one word or more, to
// a comment.
const yamlTagged = `(?:` + marker + `|[^\s#])(?:` + marker + `|\S)*(?:[ \t]+(?:` + marker + `|[^\s#])(?:` + marker + `|\S)*)*`

// yamlRefLine is a YAML line whose value a tag makes a reference to a
// secret, not the secret: !secret name, !env VAR, !include file, Ansible's
// !vault, CloudFormation's !Ref and the like.
var yamlRefLine = regexp.MustCompile(`(?i)^[ \t]*(?:-[ \t]+)?[^:\r\n]*:[ \t]*!(?:secret|env|include|vault|ref|sub|getatt|importvalue|findinmap)\b`)

// authQuoted is a quoted part of an HTTP credential or of one of a scheme's
// parameters, such as Digest's username="u", in double or single quotes.
const authQuoted = `"[^"\r\n]*"|'[^'\r\n]*'`

// authParam is an HTTP credential or one of a scheme's parameters: a token
// that may hold quoted parts, a marker taken whole.
const authParam = `(?:` + authQuoted + `|` + marker + `|[^\s,"'])+`

// authSep is the comma between two of a scheme's parameters, on one line:
// in code and JSON a comma that ends a line ends the value.
const authSep = `[ \t]*,[ \t]*`

// authLineValue is the credential, or all of a scheme's comma-separated
// parameters, of a header whose value is the rest of a line of its own:
// it does not end in a colon, as a YAML mapping key does.
const authLineValue = `(?:` + authParam + authSep + `)*(?:` + authQuoted + `|` + marker + `|[^\s,"'])*(?:` + authQuoted + `|` + marker + `|[^\s,"':])`

// authScheme is an HTTP authentication scheme: Bearer, Basic, Digest,
// Negotiate, AWS4-HMAC-SHA256 and the like.
const authScheme = `[a-z][a-z0-9._~+/-]*`

var redactions = []redaction{
	// A complete PEM private key block, then one cut off by the size cap.
	// PGP armour ends in "KEY BLOCK".
	{re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`), repl: "[REDACTED PRIVATE KEY]", hint: []string{"private key"}},
	{re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*`), repl: "[REDACTED PRIVATE KEY]", hint: []string{"private key"}},
	// Well-known token formats.
	{re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b`), repl: "[REDACTED AWS KEY ID]", hint: []string{"akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa"}},
	{re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), repl: "[REDACTED GITHUB TOKEN]", hint: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
	{re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,}\b`), repl: "[REDACTED GITHUB TOKEN]", hint: []string{"github_pat_"}},
	// Slack bot, user, app-level, refresh and rotating tokens.
	{re: regexp.MustCompile(`\b(?:xox[abeposr](?:\.xox[bp])?|xapp)-[A-Za-z0-9-]{10,}`), repl: "[REDACTED SLACK TOKEN]", hint: []string{"xox", "xapp-"}},
	{re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), repl: "[REDACTED API KEY]", hint: []string{"sk-ant-"}},
	{re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}`), repl: "[REDACTED API KEY]", hint: []string{"sk-"}},
	{re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), repl: "[REDACTED JWT]", hint: []string{"eyj"}},
	// GitLab personal, runner, pipeline trigger, deploy, OAuth and other tokens.
	{re: regexp.MustCompile(`\bgl(?:pat|rt|rtr|ptt|dt|soat|ft|imt|agent|oas|cbt|ffct)-[A-Za-z0-9_-]{20,}`), repl: "[REDACTED GITLAB TOKEN]", hint: []string{"glpat-", "glrt-", "glrtr-", "glptt-", "gldt-", "glsoat-", "glft-", "glimt-", "glagent-", "gloas-", "glcbt-", "glffct-"}},
	{re: regexp.MustCompile(`\b(?:[sr]k_(?:live|test)_[A-Za-z0-9]{20,}|whsec_[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})`), repl: "[REDACTED API KEY]", hint: []string{"k_live_", "k_test_", "whsec_", "aiza", "hf_", "npm_", "pypi-"}},
	{re: regexp.MustCompile(`\bAGE-SECRET-KEY-1[0-9A-Z]{50,}`), repl: "[REDACTED AGE KEY]", hint: []string{"age-secret-key-1"}},
	// Google OAuth access tokens (ya29.c. ones included), DigitalOcean
	// personal, OAuth and refresh tokens, the key in an Azure storage or
	// Service Bus connection string or in the JSON az storage account keys
	// list prints, and the signature of an Azure shared access signature URL.
	{re: regexp.MustCompile(`\bya29\.[0-9A-Za-z_.-]{20,}`), repl: "[REDACTED GCP TOKEN]", hint: []string{"ya29."}},
	{re: regexp.MustCompile(`\bdo[opr]_v1_[a-f0-9]{64}\b`), repl: "[REDACTED DIGITALOCEAN TOKEN]", hint: []string{"_v1_"}},
	{re: regexp.MustCompile(`(?i)\b((?:Account|SharedAccess)Key[ \t]*=[ \t]*)((?:` + marker + `|[^;\s"'])+)`), repl: "${1}[REDACTED AZURE KEY]", val: 2, hint: []string{"accountkey", "sharedaccesskey"}},
	{re: regexp.MustCompile(`("keyName"\s*:\s*"[^"]*"[^{}]*?"value"\s*:\s*)("[^"]*")`), repl: `${1}"[REDACTED AZURE KEY]"`, val: 2, hint: []string{`"keyname"`}},
	{re: regexp.MustCompile(`(?i)([?&;]sig=)((?:` + marker + `|[^&;\s"'#<>])+)`), repl: "${1}[REDACTED AZURE SAS]", val: 2, hint: []string{"sig="}},
	// The body and end of a PEM private key or PGP secret key whose start was
	// cut off, as when output is read in pieces: lines of base64, then up to
	// two short ones, as the body's last line and a PGP checksum ("=" and
	// four characters) can be, then the END line, indented or not, as in a
	// YAML block scalar.
	{re: regexp.MustCompile(`(?m)(?:^[ \t]*[A-Za-z0-9+/=]{16,}\r?\n)+(?:^[ \t]*[A-Za-z0-9+/=]{1,15}\r?\n){0,2}[ \t]*-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`), repl: "[REDACTED PRIVATE KEY]", hint: []string{"private key"}},
	// Credentials in URLs: everything from the user name's colon to the last
	// @ that a host follows, so a password may hold @ and /, as generated
	// ones often do. The host is any name, Docker Compose's db_1 or a name
	// that ends a sentence included, or a bracketed IPv6 address, a zone id
	// included; it must end where an address can, so an @ later in the path
	// is not taken for it. A user name an earlier rule replaced, such as an
	// access key id, still has its password replaced.
	{re: regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://(?:` + marker + `|[^/\s:])*:)((?:` + marker + `|[^\s"'<>` + "`" + `])+)@([\p{L}\p{N}._~-]+|\[[^\]\s/?#@]+\])([:/?#\s"'<>()\[\]{},;|\\!*&$=+` + "`" + `]|$)`), repl: "${1}[REDACTED]@${3}${4}", val: 2, hint: []string{"://"}},
	// A token as a URL's user name with no password, as Azure DevOps and
	// many git hosts take a personal access token.
	{re: regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([A-Za-z0-9_-]{32,})@`), repl: "${1}[REDACTED]@", val: 2, hint: []string{"://"}},
	// An Authorization (or Proxy-Authorization) header's credentials,
	// whatever the scheme (Bearer, Basic, Digest, Negotiate, ApiKey,
	// AWS4-HMAC-SHA256, ...) or none: the credential, or all the
	// comma-separated parameters, the scheme kept. The value may be on the
	// line after the name, indented or as a YAML list item, as YAML writes a
	// nested value and HTTP folds a header: it is then the rest of that
	// line, never a mapping key, so a YAML section named authorization keeps
	// its keys. The scheme may end its line, and is then taken as a value of
	// its own, with the credential on the next line, indented, and likewise
	// the rest of that line, so the next key of a YAML map or the next line
	// of a comment is not taken. A quoted name, as JSON and a Python dict
	// write it, takes a quoted value, but not a bare scheme such as "Bearer "
	// that code adds a token to.
	{re: regexp.MustCompile(`(?im)\b(authorization["']?[ \t]*:[ \t]*(?:[|>][-+0-9]*[ \t]*)?\r?\n(?:[ \t]+(?:-[ \t]+)?|-[ \t]+)(?:` + authScheme + `(?:[ \t]+|[ \t]*\r?\n[ \t]+))?)(` + authLineValue + `)([ \t]*\r?)$`), repl: "${1}[REDACTED]${3}", val: 2, hint: []string{"authorization"}},
	{re: regexp.MustCompile(`(?i)\b(authorization["'][ \t]*:[ \t]*)("(?:[^"\\\r\n]|\\.)*[^"\\\s]"|'(?:[^'\\\r\n]|\\.)*[^'\\\s]')`), repl: "${1}[REDACTED]", val: 2, hint: []string{"authorization"}},
	// A [ may open the value, as Go prints an http.Header: map[Authorization:[Bearer x]].
	{re: regexp.MustCompile(`(?i)\b(authorization[ \t]*:[ \t]*\[?(?:` + authScheme + `[ \t]+)?)((?:` + authQuoted + `|` + marker + `|[^\s,"'|>])(?:` + authQuoted + `|` + marker + `|[^\s,"'])*(?:` + authSep + authParam + `)*)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"authorization"}},
	{re: regexp.MustCompile(`(?im)\b(authorization[ \t]*:[ \t]*(?:` + authScheme + `|` + marker + `)[ \t]*\r?\n[ \t]+)(` + authLineValue + `)([ \t]*\r?)$`), repl: "${1}[REDACTED]${3}", val: 2, hint: []string{"authorization"}},
	// Kubeconfig embeds the client key and certificate as base64, in YAML or,
	// from kubectl config view -o json, in JSON.
	{re: regexp.MustCompile(`(?i)\b(client-key-data|client-certificate-data)("?[ \t]*:[ \t]*)("[^"]*"|` + word + `)`), repl: "${1}${2}[REDACTED]", val: 3, hint: []string{"-data"}},
	// A YAML key whose value is on the next line, plain or as a block
	// scalar: password:, then the value indented below it. A nested
	// mapping's "key: value" line is not taken for the value.
	{re: regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?["']?` + secretName + `["']?[ \t]*:)[ \t]*(?:[|>][-+0-9]*[ \t]*)?(?:#[^\n]*)?\r?\n(?:[ \t]*\r?\n)*[ \t]+([^\s#](?:[^:\r\n]|:\S)*:?)[ \t]*\r?$`), repl: "${1} [REDACTED]", val: 2, hint: secretWords},
	// PHP constants, as wp-config.php defines its database password and its
	// authentication keys and salts.
	{re: regexp.MustCompile(`(?i)(\bdefine\(\s*["'][A-Z0-9_]*(?:PASS|SECRET|TOKEN|KEY|SALT)[A-Z0-9_]*["']\s*,\s*)(` + quotedValue + `|(?:` + marker + `|[^\s,)])+)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"define("}},
	// .NET appSettings: <add key="DbPassword" value="..." />.
	{re: regexp.MustCompile(`(?i)(<add\s+key\s*=\s*["'][^"']*(?:PASSWORD|PWD|SECRET|TOKEN|API[_-]?KEY|CONNECTIONSTRING)[^"']*["']\s+value\s*=\s*)("[^"]*"|'[^']*')`), repl: `${1}"[REDACTED]"`, val: 2, hint: []string{"<add"}},
	// A secret name that starts its line, after export, set or a YAML list
	// dash, as in an env dump, an INI, .properties or .env file, YAML or
	// cmd's set, takes an unquoted value of several words to the end of the
	// line, or to a comment: password: correct horse battery staple. An
	// nsswitch.conf passwd line names lookup services, not a password.
	{re: regexp.MustCompile(`(?im)^([ \t]*(?:(?:export|set)[ \t]+|-[ \t]+)?["']?` + secretName + `["']?[ \t]*=[ \t]*)(` + lineValue + `)` + lineEnd), repl: "${1}[REDACTED]${3}", val: 2, hint: secretWords},
	{re: regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?["']?` + secretName + `["']?[ \t]*:[ \t]*)(` + yamlValue + `)((?:[ \t]+\\)?(?:[ \t]+#[^\r\n]*)?[ \t]*\r?)$`), repl: "${1}[REDACTED]${3}", val: 2, hint: secretWords, except: nssLine},
	// A YAML value after a tag or an anchor is the value itself, as Ansible
	// writes a password that holds {{ (password: !unsafe 'p{{w'), or as
	// !!str, !!binary or &name give one: the value after them is taken,
	// quoted or to a comment or the line's end.
	{re: regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?["']?` + secretName + `["']?[ \t]*:[ \t]*(?:[!&]\S*[ \t]+)+)(` + quotedValue + `|` + yamlTagged + `)((?:[ \t]+#[^\r\n]*)?[ \t]*\r?)$`), repl: "${1}[REDACTED]${3}", val: 2, hint: secretWords, except: yamlRefLine},
	// KEY=value and key: value pairs with a secret name, in env dumps,
	// config files and code: JSON's "password": "x", Python's
	// 'password': 'x', and PHP's, Ruby's and Perl's password => 'x'. An
	// unquoted value runs to a space outside quotes.
	{re: regexp.MustCompile(`(?i)\b(` + secretName + `)(["']?[ \t]*(?:=>|[=:])[ \t]*)(` + quotedValue + `|` + looseValue + `)`), repl: "${1}${2}[REDACTED]", val: 3, hint: secretWords, except: nssLine},
	// The same names as a command-line option with the value after a space,
	// as in ps output (--relay-token, --db-password, --client-secret), and
	// passwords well-known clients take as a short option: the mysql
	// clients' -p, sshpass -p, curl -u user:password, redis-cli -a, the
	// OpenLDAP tools' -w (and -y, the file that holds one), docker login -p,
	// sqlcmd, bcp and osql -P, the MongoDB tools' -p, OpenSSL's pass:
	// arguments and Samba's -U user%password.
	{re: regexp.MustCompile(`(?i)((?:^|\s)--?` + secretName + `[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: secretWords},
	{re: regexp.MustCompile(`((?i:\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlslap|mariadb(?:-[a-z]+)?)\b)[^\n]*?[ \t]-p)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"mysql", "mariadb"}},
	// The last -p of the command too, where it gives more than one.
	{re: regexp.MustCompile(`((?i:\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlslap|mariadb(?:-[a-z]+)?)\b)[^\n;|&]*[ \t]-p)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"mysql", "mariadb"}},
	{re: regexp.MustCompile(`(\bsshpass\b[^\n]*?[ \t]-p[ \t]*)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"sshpass"}},
	{re: regexp.MustCompile(`(\bcurl\b[^\n]*?[ \t](?:-u[ \t]*|--user(?:[ \t]+|=))["']?[^\s:"']*:)((?:` + marker + `|[^\s"'])+)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"curl"}},
	{re: regexp.MustCompile(`(\bredis-cli\b[^\n]*?[ \t]-a[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"redis-cli"}},
	{re: regexp.MustCompile(`(\bldap[a-z]*\b[^\n]*?[ \t]-[wy][ \t]*)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"ldap"}},
	{re: regexp.MustCompile(`(\bdocker\b[^\n]*?[ \t]login\b[^\n]*?[ \t]-p[ \t]*)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"docker"}},
	{re: regexp.MustCompile(`(\b(?:sqlcmd|bcp|osql)\b[^\n]*?[ \t]-P[ \t]*)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"sqlcmd", "bcp", "osql"}},
	{re: regexp.MustCompile(`(\bmongo(?:sh|dump|restore|export|import|stat|top|files)?\b[^\n]*?[ \t]-p[ \t]*)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"mongo"}},
	{re: regexp.MustCompile(`((?:^|\s)-pass(?:in|out)?[ \t]+pass:)(` + word + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"-pass"}},
	{re: regexp.MustCompile(`(\b(?:smbclient|rpcclient|smbcacls|smbget|smbmap|net)\b[^\n]*?[ \t](?:-U[ \t]*|--user(?:name)?[= \t])["']?[^\s%"']*%)((?:` + marker + `|[^\s"'])+)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"smbclient", "rpcclient", "smbcacls", "smbget", "smbmap", "net"}},
	// More clients that take a password as an argument: keytool's and
	// jarsigner's keystore and key passwords (and keytool -new), PuTTY's
	// -pw, ipmitool -P, 7-Zip's -p, zip and unzip -P, FreeRDP's /p: and
	// /gp:, nmcli's password and secret properties, aws configure set of a
	// secret key or session token, the password of an Oracle
	// user/password@db given to sqlplus and the other Oracle tools, PsExec's
	// and CrackMapExec's -p, htpasswd -b's last argument, and net use's
	// password after the share.
	{re: regexp.MustCompile(`((?i:\b(?:psexec|psexec64|paexec|crackmapexec|netexec|nxc)\b)[^\n]*?[ \t]-p[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"psexec", "paexec", "crackmapexec", "netexec", "nxc"}},
	{re: regexp.MustCompile(`(?m)(\bhtpasswd\b[^\n]*?[ \t]-[a-zA-Z]*b[a-zA-Z]*(?:[ \t]+\S+)*?[ \t]+)(` + flagValue + `)([ \t]*\r?)$`), repl: "${1}[REDACTED]${3}", val: 2, hint: []string{"htpasswd"}},
	{re: regexp.MustCompile(`((?i:\bnet[ \t]+use\b)[^\n]*?[ \t]\\\\\S+[ \t]+)(` + quotedValue + `|[^\s/*"'][^\s]*)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"net"}},
	{re: regexp.MustCompile(`(?i)((?:^|\s)-(?:src|dest)?(?:store|key)pass[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"storepass", "keypass"}},
	{re: regexp.MustCompile(`((?i:\bkeytool\b)[^\n]*?[ \t]-new[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"keytool"}},
	{re: regexp.MustCompile(`((?i:\b(?:plink|pscp|psftp|putty)\b)[^\n]*?[ \t]-pw[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"plink", "pscp", "psftp", "putty"}},
	{re: regexp.MustCompile(`(\bipmitool\b[^\n]*?[ \t]-P[ \t]*)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"ipmitool"}},
	{re: regexp.MustCompile(`((?i:\b7z[ar]?\b)[^\n]*?[ \t]-p)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"7z"}},
	{re: regexp.MustCompile(`(\b(?:zip|unzip|zipcloak|funzip)\b[^\n]*?[ \t]-P[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"zip"}},
	{re: regexp.MustCompile(`((?i:\b[a-z0-9-]*freerdp[0-9]*\b)[^\n]*?[ \t][/-]g?p:)(` + quotedValue + `|(?:` + marker + `|[^\s"'])+)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"freerdp"}},
	{re: regexp.MustCompile(`(\bnmcli\b[^\n]*?[ \t](?:password|[a-z0-9-]+\.(?:psk|password|wep-key[0-3]|pin|secrets))[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"nmcli"}},
	{re: regexp.MustCompile(`(?i)(\baws\b[^\n]*?[ \t]configure[ \t]+set[ \t]+(?:[a-z0-9_-]+\.)?(?:aws_secret_access_key|aws_session_token|aws_security_token)[ \t]+)(` + flagValue + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"configure"}},
	{re: regexp.MustCompile(`((?i:\b(?:sqlplus|sqlldr|expdp|impdp|rman|dgmgrl)\b)[^\n]*?[ \t](?:userid=)?["']?[A-Za-z0-9_$#.\\]+/)((?:` + marker + `|[^\s@"'/])+)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"sqlplus", "sqlldr", "expdp", "impdp", "rman", "dgmgrl"}},
	// The names as an XML element, and registry auth in Docker and npm
	// configuration.
	{re: regexp.MustCompile(`(?i)(<(?:password|passwd|pass|secret|token|api[_-]?key)(?:\s[^>]*)?>)([^<]+)(</)`), repl: "${1}[REDACTED]${3}", val: 2, hint: []string{"<pass", "<secret", "<token", "<api"}},
	{re: regexp.MustCompile(`(?i)("auth"[ \t]*:[ \t]*)("[^"]+")`), repl: `${1}"[REDACTED]"`, val: 2, hint: []string{`"auth"`}},
	{re: regexp.MustCompile(`(?i)(\b_auth[ \t]*=[ \t]*)(` + word + `)`), repl: "${1}[REDACTED]", val: 2, hint: []string{"_auth"}},
}

// isMarker reports whether v, a secret's value, is a marker an earlier rule
// put there, perhaps quoted, and nothing more.
func isMarker(v string) bool {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	rest, ok := strings.CutPrefix(v, "[REDACTED")
	if !ok || !strings.HasSuffix(rest, "]") {
		return false
	}
	return !strings.ContainsFunc(rest[:len(rest)-1], func(c rune) bool { return c != ' ' && (c < 'A' || c > 'Z') })
}

// redact returns s with known secrets replaced and how many it replaced.
func redact(s string) (string, int) {
	res, n, _ := redactParts([]string{s})
	return res[0], n
}

// redactAll redacts an argument vector, for audit entries and job_list: each
// argument on its own, and then all of them joined by spaces, as the command
// line they make, so that an option and its value given as two arguments
// (--db-password X, redis-cli -a X) or a client and its option (mysql, then
// -pX) are found too. An argument that holds a byte of a secret only the
// command line shows is replaced whole.
func redactAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i], _ = redact(s)
	}
	if len(in) < 2 {
		return out
	}
	joined := strings.Join(in, " ")
	hit, _ := secretBytes(joined, identity(len(joined)), len(joined), 0, len(joined))
	off := 0
	for i, s := range in {
		h := hit[off : off+len(s)]
		off += len(s) + 1
		if !slices.Contains(h, true) {
			continue
		}
		self, _ := secretBytes(s, identity(len(s)), len(s), 0, len(s))
		for k, x := range h {
			if x && !self[k] {
				out[i] = "[REDACTED]"
				break
			}
		}
	}
	return out
}

// identity maps each of n bytes to its own offset, for secretBytes on text
// that is its own source.
func identity(n int) []int32 {
	from := make([]int32, n)
	for i := range from {
		from[i] = int32(i)
	}
	return from
}

// redactSplit redacts the concatenation of parts, as redact does, and cuts
// the result back where the parts met, so a secret written across two of
// them is still found. A secret that crossed a boundary is replaced whole, in
// the part where it began.
func redactSplit(parts []string) ([]string, int) {
	res, n, _ := redactParts(parts)
	return res, n
}

// secretBytes reports which bytes of a text of n bytes are secrets that
// redaction replaces: the values of rules that name one, the whole match of
// the others. s is the text as redaction sees it, and from the offset in the
// text of each of its bytes, as cleanText returns them. It also returns how
// many secrets hold a byte of the text's [lo, hi). Offsets are 32 bits,
// enough for any page, so the maps stay small.
func secretBytes(s string, from []int32, n, lo, hi int) ([]bool, int) {
	hit, count := make([]bool, n), 0
	at := append([]int32(nil), from...) // where each byte of s came from, or -1 inside a marker
	folded, foldedOK := "", false
	for _, r := range redactions {
		if len(r.hint) > 0 {
			if !foldedOK {
				folded, foldedOK = foldCase(s), true
			}
			if !slices.ContainsFunc(r.hint, func(h string) bool { return strings.Contains(folded, h) }) {
				continue
			}
		}
		ms := r.re.FindAllStringSubmatchIndex(s, -1)
		if len(ms) == 0 {
			continue
		}
		var out strings.Builder
		out.Grow(len(s))
		nat := make([]int32, 0, len(at))
		last := 0
		for _, m := range ms {
			if r.keep(s, m) {
				continue
			}
			repl := r.re.ExpandString(nil, r.repl, s, m)
			if string(repl) == s[m[0]:m[1]] {
				continue
			}
			from, to := m[0], m[1]
			if r.val > 0 && m[2*r.val] >= 0 {
				from, to = m[2*r.val], m[2*r.val+1]
			}
			touched := false
			for _, o := range at[from:to] {
				if o >= 0 {
					hit[o] = true
					touched = touched || int(o) >= lo && int(o) < hi
				}
			}
			if touched {
				count++
			}
			out.WriteString(s[last:m[0]])
			nat = append(nat, at[last:m[0]]...)
			out.Write(repl)
			for range repl {
				nat = append(nat, -1)
			}
			last = m[1]
		}
		if last == 0 {
			continue
		}
		out.WriteString(s[last:])
		s, at, foldedOK = out.String(), append(nat, at[last:]...), false
	}
	return hit, count
}

// redactCtx is how much output on each side of a read is redacted with it.
const redactCtx = 8 << 10

// redactWindow redacts mid as part of before+mid+after, the output around it
// (up to redactCtx of each), and returns what is left of mid and how many
// secrets touched it. A secret that a read starts or ends inside, such as a
// private key, is removed whole, so where a read begins or ends cannot let
// part of one through.
func redactWindow(before, mid, after string) (string, int) {
	res, _, counts := redactParts([]string{before, mid, after})
	return res[1], counts[1]
}

// redactParts is redactSplit that also counts, for each part, the secrets
// that touched it.
func redactParts(parts []string) ([]string, int, []int) { return rewriteParts(parts, nil, redactions) }

// redactSegs is redactWindow for a read in segments, between each two of
// which a note goes: the segments are redacted as one text with the output
// around them, and a secret that touches several counts once.
func redactSegs(before string, segs []string, after string) ([]string, int) {
	parts := make([]string, 0, len(segs)+2)
	groups := make([]int, 0, len(segs)+2)
	parts, groups = append(parts, before), append(groups, 0)
	for _, s := range segs {
		parts, groups = append(parts, s), append(groups, 1)
	}
	parts, groups = append(parts, after), append(groups, 2)
	res, _, counts := rewriteParts(parts, groups, redactions)
	return res[1 : len(res)-1], counts[1]
}

// redactAround is redactSegs for a read whose text before it is in segments
// too: it returns that, the read and the text after it, redacted, and how
// many secrets touched the read.
func redactAround(before, segs []string, after string) ([]string, []string, string, int) {
	parts := make([]string, 0, len(before)+len(segs)+1)
	groups := make([]int, 0, cap(parts))
	for _, s := range before {
		parts, groups = append(parts, s), append(groups, 0)
	}
	for _, s := range segs {
		parts, groups = append(parts, s), append(groups, 1)
	}
	parts, groups = append(parts, after), append(groups, 2)
	res, _, counts := rewriteParts(parts, groups, redactions)
	return res[:len(before)], res[len(before) : len(before)+len(segs)], res[len(res)-1], counts[1]
}

// rewriteParts applies rules to the concatenation of parts as redactParts
// does. A match its replacement leaves as it was, such as a [REDACTED]
// marker an earlier pass put there, is neither changed nor counted, nor is
// one its rule keeps, as one whose value is such a marker (see keep), so
// redacting text again counts only the secrets it newly finds. groups, when
// given, puts each part in a group, the parts of one group next to each
// other, and counts are per group: a match counts once in each group it
// touches.
func rewriteParts(parts []string, groups []int, rules []redaction) ([]string, int, []int) {
	ends := make([]int, len(parts)) // where each part ends in s
	var b strings.Builder
	for i, p := range parts {
		b.WriteString(p)
		ends[i] = b.Len()
	}
	group := func(i int) int { return i }
	ngroups := len(parts)
	if groups != nil {
		group = func(i int) int { return groups[i] }
		ngroups = 0
		if len(groups) > 0 {
			ngroups = groups[len(groups)-1] + 1
		}
	}
	s, n, counts := b.String(), 0, make([]int, ngroups)
	folded, foldedOK := "", false // s, case-folded, for the rules' hints
	for _, r := range rules {
		if len(r.hint) > 0 {
			if !foldedOK {
				folded, foldedOK = foldCase(s), true
			}
			if !slices.ContainsFunc(r.hint, func(h string) bool { return strings.Contains(folded, h) }) {
				continue
			}
		}
		ms := r.re.FindAllStringSubmatchIndex(s, -1)
		if len(ms) == 0 {
			continue
		}
		foldedOK = false
		pre := append([]int(nil), ends...) // the ends in s, before this pass moves them
		var out strings.Builder
		last, k := 0, 0
		for _, m := range ms {
			if r.keep(s, m) {
				continue
			}
			repl := r.re.ExpandString(nil, r.repl, s, m)
			if string(repl) == s[m[0]:m[1]] {
				continue
			}
			n++
			// Count the match in every group it overlaps: from the first part
			// ending after it starts, until one ends at or after its end.
			counted := -1
			for i := sort.SearchInts(pre, m[0]+1); i < len(pre); i++ {
				if g := group(i); g != counted {
					counts[g]++
					counted = g
				}
				if pre[i] >= m[1] {
					break
				}
			}
			// Ends before the match keep their place, shifted by what earlier
			// replacements changed; ends inside it move past its replacement.
			for ; k < len(ends) && ends[k] <= m[0]; k++ {
				ends[k] += out.Len() - last
			}
			out.WriteString(s[last:m[0]])
			out.Write(repl)
			for ; k < len(ends) && ends[k] < m[1]; k++ {
				ends[k] = out.Len()
			}
			last = m[1]
		}
		for ; k < len(ends); k++ {
			ends[k] += out.Len() - last
		}
		out.WriteString(s[last:])
		s = out.String()
	}
	res := make([]string, len(parts))
	start := 0
	for i, e := range ends {
		res[i], start = s[start:e], e
	}
	return res, n, counts
}

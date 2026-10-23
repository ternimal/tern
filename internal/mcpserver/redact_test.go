// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct {
		in        string
		gone      string // must not survive
		keep      string // must survive
		wantCount int
	}{
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----\nafter", "b3BlbnNzaA", "after", 1},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA cut off by the cap", "MIIEpAIBAAKCAQEA", "", 1},
		{"key AKIAIOSFODNN7EXAMPLE in a log", "AKIAIOSFODNN7EXAMPLE", "in a log", 1},
		{"token ghp_" + strings.Repeat("a", 36) + " end", "ghp_", " end", 1},
		{"x-api: sk-ant-api03-" + strings.Repeat("Z", 30), "sk-ant-api03", "x-api", 1},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "dozjgNryP4J3", "jwt", 1},
		{"postgres://app:s3cr3t@db:5432/x", "s3cr3t", "postgres://app:", 1},
		{"Authorization: Bearer abc.def.ghi", "abc.def.ghi", "Authorization: Bearer", 1},
		{"DB_PASSWORD=hunter2\nTERN_TOKEN=abcdefgh12345678\nPATH=/usr/bin", "hunter2", "PATH=/usr/bin", 2},
		{`secret: "multi word value"`, "multi word value", "secret:", 1},
		{"api_key = 'quoted'", "quoted", "api_key", 1},
		{"redis://:r3dispass@cache:6379", "r3dispass", "redis://:", 1},
		{"mysql --password hunter2 -h db", "hunter2", "-h db", 1},
		{"<Password>xml-secret</Password>", "xml-secret", "</Password>", 1},
		{`{"auths":{"r.io":{"auth":"dXNlcjpwYXNz"}}}`, "dXNlcjpwYXNz", `"auths"`, 1},
		{"_auth=dXNlcjpwYXNz", "dXNlcjpwYXNz", "_auth", 1},
		{"key glpat-" + strings.Repeat("x", 20), "glpat-", "key", 1},
		{"stripe sk_live_" + strings.Repeat("a", 24), "sk_live_", "stripe", 1},
		{"AGE-SECRET-KEY-1" + strings.Repeat("Q", 58), "QQQQ", "", 1},
		// The rest of a key whose BEGIN line an earlier read returned.
		{"MIIEpAIBAAKCAQEAxyz0123456789ab\nZm9vYmFyYmF6cXV1eHF1dXo=\n-----END RSA PRIVATE KEY-----\nnext", "MIIEpAIBAAKCAQEA", "next", 1},
	}
	for _, c := range cases {
		got, n := redact(c.in)
		if strings.Contains(got, c.gone) {
			t.Errorf("redact(%q) kept %q: %q", c.in, c.gone, got)
		}
		if c.keep != "" && !strings.Contains(got, c.keep) {
			t.Errorf("redact(%q) lost %q: %q", c.in, c.keep, got)
		}
		if n < c.wantCount {
			t.Errorf("redact(%q) count = %d, want >= %d", c.in, n, c.wantCount)
		}
	}
	// Ordinary output passes through untouched.
	for _, s := range []string{
		"Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 50G 20G 30G 40% /",
		"enter the password when prompted",
		"tokens: 3 of 5 used",
		"https://example.com:8443/path",
		"usage: tool --token -v",
	} {
		if got, n := redact(s); got != s || n != 0 {
			t.Errorf("redact(%q) changed ordinary text: %q (%d)", s, got, n)
		}
	}
}

// Secret names need not end in the secret word, and a URL password may hold
// @ and /, as generated ones and base64 do.
func TestRedactNamesAndURLPasswords(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"SECRET_KEY = 'django-insecure-q1w2e3r4t5y6u7i8o9p0'", "SECRET_KEY = [REDACTED]"},
		{"SECRET_KEY_BASE=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "SECRET_KEY_BASE=[REDACTED]"},
		{"export MYSQL_PWD=Hunter2Hunter2", "export MYSQL_PWD=[REDACTED]"},
		{"APP_KEY=base64:Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5", "APP_KEY=[REDACTED]"},
		{"DB_PASSWORD_FILE=/run/secrets/db", "DB_PASSWORD_FILE=[REDACTED]"},
		{"DATABASE_URL=postgres://admin:P@ssw0rdXyz@db.internal:5432/app", "DATABASE_URL=postgres://admin:[REDACTED]@db.internal:5432/app"},
		{"mongodb://admin:Zm9v/YmFyYmF6+cXV4@mongo:27017/admin", "mongodb://admin:[REDACTED]@mongo:27017/admin"},
		{"https://AKIDEXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY@s3.example.com/bucket", "https://AKIDEXAMPLE:[REDACTED]@s3.example.com/bucket"},
		{"(see https://deploy:s3cret@git.example.com)", "(see https://deploy:[REDACTED]@git.example.com)"},
		{`{"url":"https://u:p@h.example/x","by":"a@b"}`, `{"url":"https://u:[REDACTED]@h.example/x","by":"a@b"}`},
		{"https://ci:t0ken@registry.example.org/@scope%2fpkg", "https://ci:[REDACTED]@registry.example.org/@scope%2fpkg"},
		// Not secrets: the working directory, words that only start like one.
		{"PWD=/home/bob\nOLDPWD=/tmp", "PWD=/home/bob\nOLDPWD=/tmp"},
		{"TOKENIZER=bert tokens: 3 of 5 used", "TOKENIZER=bert tokens: 3 of 5 used"},
		{"https://example.com/@user and ssh://git@github.com:22/r", "https://example.com/@user and ssh://git@github.com:22/r"},
	} {
		if got, _ := redact(c.in); got != c.want {
			t.Errorf("redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Secrets in the config and command-line syntax people commonly use: PHP
// constants and arrays, Python dicts, camelCase and plural names, YAML values
// on the next line, .NET appSettings, and passwords the mysql clients,
// sshpass and curl take as arguments.
func TestRedactConfigSyntax(t *testing.T) {
	const v = "Hunter2xyzzy"
	for _, in := range []string{
		`define( 'DB_PASSWORD', 'Hunter2xyzzy' );`,
		`define('AUTH_KEY', 'Hunter2xyzzy');`,
		`define("NONCE_SALT", "Hunter2xyzzy");`,
		`{'user': 'admin', 'password': 'Hunter2xyzzy'}`,
		`'password' => 'Hunter2xyzzy',`,
		`:password => "Hunter2xyzzy"`,
		`password => 'Hunter2xyzzy'`,
		`"secretKey": "Hunter2xyzzy"`,
		`jwtSecretKey=Hunter2xyzzy`,
		`dbPassword=Hunter2xyzzy`,
		`apiKey: Hunter2xyzzy`,
		`clientSecret = "Hunter2xyzzy"`,
		`PASSWORDS=Hunter2xyzzy`,
		`API_KEYS=Hunter2xyzzy`,
		`"password": "abc\"Hunter2xyzzy"`,
		"password:\n  Hunter2xyzzy",
		"db:\n  password: |\n    Hunter2xyzzy\n  host: db\n",
		"- password: >-\n\n    Hunter2xyzzy",
		`<add key="DbPassword" value="Hunter2xyzzy" />`,
		`mysql -uroot -pHunter2xyzzy`,
		`mysqldump -h db -pHunter2xyzzy app`,
		`mariadb-dump -p'Hunter2xyzzy' app`,
		`curl -u admin:Hunter2xyzzy https://x`,
		`curl -s --user admin:Hunter2xyzzy https://x`,
		`curl -uadmin:Hunter2xyzzy https://x`,
		`sshpass -p Hunter2xyzzy ssh host`,
		`SSHPASS=Hunter2xyzzy`,
		`DB_PASS=Hunter2xyzzy`,
		`smtp.pass: Hunter2xyzzy`,
	} {
		if got, n := redact(in); strings.Contains(got, v) || n != 1 {
			t.Errorf("redact(%q) = %q (%d)", in, got, n)
		}
	}
	// Look-alikes that hold no secret are left as they are.
	for _, s := range []string{
		"secretKeyRef:\n  name: db",
		"db_password:\n    file: ./db_password.txt",
		"mkdir -p /tmp/x && ssh -p 22 host && docker run -p 8080:80 img",
		"ps -u root; git push -u origin main",
		"mysql -p db",
		"define('WP_DEBUG', true);",
		"pass: 3, fail: 0, BYPASS=1",
	} {
		if got, n := redact(s); got != s || n != 0 {
			t.Errorf("redact(%q) changed ordinary text: %q (%d)", s, got, n)
		}
	}
}

// URL credentials are redacted whatever the host looks like: a Docker Compose
// name with an underscore, a name that ends a sentence, an IPv6 address with
// a zone id, a name followed by punctuation.
func TestRedactURLHosts(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"postgres://admin:Hunter2xyzzy@db.internal.", "postgres://admin:[REDACTED]@db.internal."},
		{"DATABASE_URL=postgres://app:Hunter2xyzzy@db_1:5432/app", "DATABASE_URL=postgres://app:[REDACTED]@db_1:5432/app"},
		{"redis://default:Hunter2xyzzy@cache_redis", "redis://default:[REDACTED]@cache_redis"},
		{"redis://:Hunter2xyzzy@[fe80::1%eth0]:6379", "redis://:[REDACTED]@[fe80::1%eth0]:6379"},
		{"see https://u:Hunter2xyzzy@host!", "see https://u:[REDACTED]@host!"},
		{"use `mysql://u:Hunter2xyzzy@db`", "use `mysql://u:[REDACTED]@db`"},
		{"amqp://u:Hunter2xyzzy@rabbit.example.com.au/vhost", "amqp://u:[REDACTED]@rabbit.example.com.au/vhost"},
	} {
		if got, _ := redact(c.in); got != c.want {
			t.Errorf("redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Cloud credentials beyond AWS: Azure storage keys and SAS signatures, Google
// OAuth access tokens and DigitalOcean tokens get typed markers.
func TestRedactCloudTokens(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	for _, c := range []struct{ in, gone, marker string }{
		{"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=SGVudGVyMnh5enp5SGVudGVyMnh5enp5==;EndpointSuffix=core.windows.net", "SGVudGVy", "AccountKey=[REDACTED AZURE KEY];EndpointSuffix"},
		{"Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=SGVudGVyMnh5enp5=", "SGVudGVy", "SharedAccessKey=[REDACTED AZURE KEY]"},
		{"https://acct.blob.core.windows.net/c/b?sv=2022-11-02&ss=b&sig=SGVudGVy%2Bxyzzy%3D&se=2026", "SGVudGVy", "&sig=[REDACTED AZURE SAS]&se=2026"},
		{"Authorization: Bearer ya29.a0AfH6SMBSGVudGVyMnh5enp5SGVudGVy", "SGVudGVy", "Bearer [REDACTED GCP TOKEN]"},
		{"export DIGITALOCEAN_ACCESS_TOKEN=dop_v1_" + hex64, hex64, "[REDACTED DIGITALOCEAN TOKEN]"},
	} {
		got, n := redact(c.in)
		if strings.Contains(got, c.gone) || !strings.Contains(got, c.marker) || n != 1 {
			t.Errorf("redact(%q) = %q (%d)", c.in, got, n)
		}
	}
}

// A secret an earlier rule replaced is not replaced again by a rule that
// sees it as a value: the typed marker stays whole and counts once.
func TestRedactKeepsTypedMarkers(t *testing.T) {
	gh := "ghp_" + strings.Repeat("a", 36)
	for _, c := range []struct{ in, want string }{
		{"API_KEY=sk-ant-api03-" + strings.Repeat("Z", 30), "API_KEY=[REDACTED API KEY]"},
		{"TOKEN=" + gh, "TOKEN=[REDACTED GITHUB TOKEN]"},
		{`"password": "` + gh + `"`, `"password": "[REDACTED GITHUB TOKEN]"`},
		{"tool --token " + gh, "tool --token [REDACTED GITHUB TOKEN]"},
		{"<token>" + gh + "</token>", "<token>[REDACTED GITHUB TOKEN]</token>"},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "Authorization: Bearer [REDACTED JWT]"},
	} {
		if got, n := redact(c.in); got != c.want || n != 1 {
			t.Errorf("redact(%q) = %q (%d), want %q (1)", c.in, got, n, c.want)
		}
	}
}

// Redacting redacted text again changes nothing and counts nothing: the
// markers are not secrets. What a second pass counts is what it newly found.
func TestRedactAgainFindsOnlyNew(t *testing.T) {
	in := "env DB_PASSWORD=hunter2 postgres://app:s3cr3t@db/x Authorization: Bearer abc <password>p</password> " +
		`{"auth": "dXNlcjpwYXNz"} _auth=x token ghp_` + strings.Repeat("a", 36)
	once, n := redact(in)
	if n != 7 {
		t.Fatalf("first pass found %d secrets in %q: %q", n, in, once)
	}
	if twice, m := redact(once); twice != once || m != 0 {
		t.Errorf("a second pass changed %q to %q, counting %d", once, twice, m)
	}
	if _, m := redact(once + " API_KEY=new"); m != 1 {
		t.Errorf("a second pass over a new secret counted %d", m)
	}
}

func TestRedactSplit(t *testing.T) {
	parts := []string{"ok DB_PASS", "WORD=hunter2 and AKIAIOSFO", "DNN7EXAMPLE done", ""}
	got, n := redactSplit(parts)
	joined := strings.Join(got, "")
	want, wn := redact(strings.Join(parts, ""))
	if joined != want || n != wn {
		t.Fatalf("joined %q (%d), want %q (%d)", joined, n, want, wn)
	}
	if len(got) != len(parts) || strings.Contains(joined, "hunter2") || strings.Contains(joined, "IOSFODNN7") {
		t.Fatalf("parts = %q", got)
	}
	// Each secret is replaced whole in the part where it began.
	if !strings.HasPrefix(got[0], "ok DB_PASSWORD=[REDACTED]") || !strings.HasSuffix(got[1], "[REDACTED AWS KEY ID]") || got[2] != " done" {
		t.Fatalf("parts = %q", got)
	}
	if got, n := redactSplit([]string{"plain", "text"}); n != 0 || got[0] != "plain" || got[1] != "text" {
		t.Fatalf("nothing to redact: %q %d", got, n)
	}
}

// A command-line option whose name says its value is secret has the value
// redacted, whatever the rest of its name, and so do the passwords
// well-known clients take as a short option. Look-alikes stay as they are.
func TestRedactOptions(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{"/usr/local/bin/ternd --token AgentTok-123 --addr :2222", "AgentTok-123"},
		{"/usr/local/bin/ternr --relay-token RelayTok-456 --addr :2223", "RelayTok-456"},
		{"tern api --api-token ApiTok-789 --api-addr 127.0.0.1:8080", "ApiTok-789"},
		{"app --db-password DbPw-Hunter2 --port 5432", "DbPw-Hunter2"},
		{"az login --service-principal -u app --client-secret ClientSec-1", "ClientSec-1"},
		{"tool --access-token AccessTok-2", "AccessTok-2"},
		{"tool --auth-token AuthTok-3", "AuthTok-3"},
		{"mc alias set s3 https://s3 AKEY --secret-key SecretKey-4", "SecretKey-4"},
		{"redis-cli -h cache -a RedisPass-5", "RedisPass-5"},
		{"ldapsearch -x -D cn=admin -w LdapPw-6", "LdapPw-6"},
		{"ldapmodify -D cn=admin -wLdapPw-7 -f x.ldif", "LdapPw-7"},
		{"docker login -u ci -p DockerPw-8 registry.example", "DockerPw-8"},
		{"sqlcmd -S db -U sa -P SqlPw-9", "SqlPw-9"},
		{"mongosh -u admin -p MongoPw-10", "MongoPw-10"},
		{"mongodump --uri x -p MongoPw-11", "MongoPw-11"},
		{"openssl pkcs12 -in a.p12 -passin pass:P12Pw-12", "P12Pw-12"},
		{"openssl enc -aes256 -pass pass:EncPw-13 -in f", "EncPw-13"},
		{"smbclient //fs/share -U alice%SmbPw-14", "SmbPw-14"},
		{"rpcclient -U 'CORP\\bob%SmbPw-15' fs", "SmbPw-15"},
		{"mysql -uroot -pMyPw-16", "MyPw-16"},
		{"sshpass -p SshPw-17 ssh host", "SshPw-17"},
		{"curl -u admin:CurlPw-18 https://x", "CurlPw-18"},
	} {
		if got, n := redact(c.in); strings.Contains(got, c.secret) || n != 1 {
			t.Errorf("redact(%q) = %q (%d)", c.in, got, n)
		}
	}
	for _, s := range []string{
		"docker run -p 8080:80 img && ssh -p 22 host",
		"mysql -p db",
		"tool --tokens 3 --max-tokens 100 --tokenizer bert",
		"usage: tool --token -v",
		"redis-cli -h cache ping",
		"openssl enc -pass env:PW -in f",
		"net use x: \\\\fs\\share",
	} {
		if got, n := redact(s); got != s || n != 0 {
			t.Errorf("redact(%q) changed ordinary text: %q (%d)", s, got, n)
		}
	}
}

// A value is redacted whole: one a marker only partly covers, as when a
// token rule took its first part, one with a quote inside it or never
// closed, and one that starts with a marker someone wrote there. A URL
// whose user name a rule already replaced keeps no password. Typed markers
// still count once, and redacting again counts nothing.
func TestRedactWholeValues(t *testing.T) {
	gh := "ghp_" + strings.Repeat("A", 36)
	for _, c := range []struct {
		in, secret string
		count      int
	}{
		{"AWS_CREDENTIALS=AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", 2},
		{"DB_PASSWORD=sk-proj-abcdefghijklmnopqrstuvwxyz!Tail123", "Tail123", 2},
		{`DB_PASSWORD=abc"Hunter2xyzzy`, "Hunter2xyzzy", 1},
		{`DB_PASSWORD="Hunter2xyzzy`, "Hunter2xyzzy", 1},
		{`DB_PASSWORD='Hunter2 xyzzy`, "xyzzy", 1},
		{"DB_PASSWORD=[REDACTED]Hunter2xyzzy", "Hunter2xyzzy", 1},
		{"DB_PASSWORD=[REDACTED API KEY]Hunter2xyzzy", "Hunter2xyzzy", 1},
		{"s3a://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY@bucket/path", "wJalrXUtnFEMI", 2},
		{"https://" + gh + ":Hunter2xyzzy@github.example/repo", "Hunter2xyzzy", 2},
		{"tool --token " + gh + "Tail99", "Tail99", 1},
		{"Authorization: Bearer [REDACTED]Hunter2xyzzy", "Hunter2xyzzy", 1},
	} {
		got, n := redact(c.in)
		if strings.Contains(got, c.secret) || n != c.count {
			t.Errorf("redact(%q) = %q (%d, want %d)", c.in, got, n, c.count)
		}
		if again, m := redact(got); again != got || m != 0 {
			t.Errorf("redacting %q again gave %q (%d)", got, again, m)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"API_KEY=sk-proj-" + strings.Repeat("b", 30), "API_KEY=[REDACTED API KEY]"},
		{"export DB_PASSWORD=" + gh, "export DB_PASSWORD=[REDACTED GITHUB TOKEN]"},
		{`"password": "` + gh + `"`, `"password": "[REDACTED GITHUB TOKEN]"`},
		{"postgres://u:" + gh + "@db/x", "postgres://u:[REDACTED GITHUB TOKEN]@db/x"},
		{`{"password": "x", "user": "y"}`, `{"password": [REDACTED], "user": "y"}`},
	} {
		if got, n := redact(c.in); got != c.want || n != 1 {
			t.Errorf("redact(%q) = %q (%d), want %q", c.in, got, n, c.want)
		}
	}
}

// Token forms in current use: Google OAuth tokens with a dot after ya29,
// Slack refresh and app-level tokens, Azure storage keys as az prints them
// and Azure DevOps tokens as a URL's user name, Stripe webhook secrets, and
// GitLab runner and deploy tokens.
func TestRedactTokenForms(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{"access_token ya29.c.c0ASRK0GZsVlxSGVudGVyMnh5enp5SGVudGVy", "c0ASRK0GZ"},
		// The Slack forms are put together here, so the file holds no
		// string a secret scanner takes for a real token.
		{"slack " + "xox" + "e-1-My0xLTEyMzQtNTY3OC05MDEyMzQ1Njc4OTAx", "My0xLTEy"},
		{"slack " + "xox" + "e.xox" + "p-1-My0xLTEyMzQtNTY3OC05MDEyMzQ1", "My0xLTEy"},
		{"slack xapp-1-A0123456789-1234567890123-abcdefabcdef", "abcdefabcdef"},
		{"[{\"keyName\": \"key1\",\n  \"permissions\": \"FULL\",\n  \"value\": \"" + strings.Repeat("Ab3/", 21) + "Ab==\"}]", "Ab3/Ab3/"},
		{"origin  https://q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0z1x2c3v4b5n6m7@dev.azure.com/org/p/_git/r (fetch)", "q2w3e4r5"},
		{"STRIPE_WEBHOOK whsec_" + strings.Repeat("a1", 16), "a1a1a1a1"},
		{"runner glrt-" + strings.Repeat("x", 20), "xxxxxxxx"},
		{"deploy gldt-" + strings.Repeat("y", 20), "yyyyyyyy"},
	} {
		if got, n := redact(c.in); strings.Contains(got, c.secret) || n != 1 {
			t.Errorf("redact(%q) = %q (%d)", c.in, got, n)
		}
	}
	// A short user name in a URL is no token.
	s := "ssh://deploy@example.com/o/r and https://bob@example.com/"
	if got, n := redact(s); got != s || n != 0 {
		t.Errorf("redact(%q) = %q (%d)", s, got, n)
	}
}

// Rules whose hints a text lacks are not run, but none is skipped on text
// it matches: case folding maps the letters that fold to ASCII ones.
func TestRedactionHintsHold(t *testing.T) {
	for _, s := range []string{"Account\u212aey=hunter2", "DB_PA\u017f\u017fWORD=hunter2", "X_\u017fECRET_KEY: hunter2"} {
		if got, n := redact(s); n != 1 || strings.Contains(got, "hunter2") {
			t.Errorf("redact(%q) = %q (%d)", s, got, n)
		}
	}
}

// A prompt for a password is not a password: the value must be on the line.
func TestRedactKeepsNextLine(t *testing.T) {
	in := "Password: \nuser@host:~$ ls\n"
	if out, n := redact(in); out != in || n != 0 {
		t.Fatalf("redact(%q) = %q, %d", in, out, n)
	}
	for in, want := range map[string]string{
		"password: hunter2\n":             "password: [REDACTED]\n",
		`{"api_key": "abc"}`:              `{"api_key": [REDACTED]}`,
		"env DB_PASSWORD=x y":             "env DB_PASSWORD=[REDACTED] y",
		"    client-key-data: LS0tLS1C":   "    client-key-data: [REDACTED]",
		`{"client-key-data": "LS0tLS1C"}`: `{"client-key-data": [REDACTED]}`,
		"-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----": "[REDACTED PRIVATE KEY]",
	} {
		if out, _ := redact(in); out != want {
			t.Errorf("redact(%q) = %q, want %q", in, out, want)
		}
	}
}

// keyLines is n characters of base64 in the 64-character lines of a PEM or
// PGP body, drawn from seed.
func keyLines(n, seed int) []string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var lines []string
	for i := 0; n > 0; i++ {
		var b strings.Builder
		for j := range min(n, 64) {
			b.WriteByte(alpha[(seed+i*31+j*17+i*j)%64])
		}
		lines = append(lines, b.String())
		n -= min(n, 64)
	}
	return lines
}

// The rest of a private key whose start a read does not hold, as after a
// buffer dropped it or a recording was cut, is redacted whatever the length
// of its last body line, a PGP key's checksum line after it included, and
// indented, as in a YAML block scalar. A certificate's end is not a key's.
func TestRedactCutKeyTail(t *testing.T) {
	for _, c := range []struct {
		name, end, indent string
		lines             []string
	}{
		{"PEM, last line of 4", "-----END RSA PRIVATE KEY-----", "", keyLines(24*64+4, 1)},
		{"PEM, last line of 12", "-----END PRIVATE KEY-----", "", keyLines(24*64+12, 2)},
		{"PEM, last line of 60", "-----END EC PRIVATE KEY-----", "", keyLines(4*64+60, 3)},
		{"PGP, checksum after a full line", "-----END PGP PRIVATE KEY BLOCK-----", "", append(keyLines(20*64, 4), "=Ab1+")},
		{"PGP, checksum after a short line", "-----END PGP PRIVATE KEY BLOCK-----", "", append(keyLines(20*64+9, 5), "=Ab1+")},
		{"PEM in YAML", "-----END RSA PRIVATE KEY-----", "    ", keyLines(10*64+3, 6)},
	} {
		var b strings.Builder
		for _, l := range c.lines[1:] { // the first line went with the BEGIN line
			b.WriteString(c.indent + l + "\n")
		}
		b.WriteString(c.indent + c.end + "\nnext line\n")
		got, n := redact(b.String())
		for _, l := range c.lines[1:] {
			if len(l) >= 8 && strings.Contains(got, l) {
				t.Errorf("%s: a body line is shown: %q", c.name, got)
				break
			}
		}
		if n != 1 || !strings.Contains(got, "next line") {
			t.Errorf("%s: %q (%d)", c.name, got, n)
		}
	}
	cert := strings.Join(keyLines(10*64+4, 7), "\n") + "\n-----END CERTIFICATE-----\n"
	if got, n := redact(cert); got != cert || n != 0 {
		t.Errorf("a certificate's end was redacted: %q (%d)", got, n)
	}
}

// A secret name that starts its line takes an unquoted value of several
// words to the end of the line, as env dumps, INI, .properties and .env
// files, YAML and cmd's set write one; in YAML a comment ends it. Elsewhere
// on a line an unquoted value ends at a space, and a quoted one at its quote.
func TestRedactLineValues(t *testing.T) {
	const v = "correct horse battery staple"
	for in, want := range map[string]string{
		"password: " + v:                                 "password: [REDACTED]",
		"db:\n  password: " + v + "\n":                   "db:\n  password: [REDACTED]\n",
		"password = " + v:                                "password = [REDACTED]",
		"db.password=" + v + "\r\n":                      "db.password=[REDACTED]\r\n",
		"DB_PASSWORD=" + v:                               "DB_PASSWORD=[REDACTED]",
		"export DB_PASSWORD=" + v:                        "export DB_PASSWORD=[REDACTED]",
		"set PASSWORD=" + v:                              "set PASSWORD=[REDACTED]",
		"Password: " + v:                                 "Password: [REDACTED]",
		"  - DB_PASSWORD=" + v:                           "  - DB_PASSWORD=[REDACTED]",
		"api_key: " + v + " # rotated":                   "api_key: [REDACTED] # rotated",
		"x DB_PASSWORD=correct horse":                    "x DB_PASSWORD=[REDACTED] horse",
		`password: "` + v + `" extra`:                    `password: [REDACTED] extra`,
		"password => correct horse":                      "password => [REDACTED] horse",
		"TOKEN=ghp_" + strings.Repeat("a", 36) + " (ci)": "TOKEN=[REDACTED]",
	} {
		if got, n := redact(in); got != want || n == 0 {
			t.Errorf("redact(%q) = %q (%d), want %q", in, got, n, want)
		}
	}
	// A value of one word is as it was: a typed marker counts once.
	if got, n := redact("TOKEN=ghp_" + strings.Repeat("a", 36)); got != "TOKEN=[REDACTED GITHUB TOKEN]" || n != 1 {
		t.Errorf("one word: %q (%d)", got, n)
	}
}

// A value of several words stops before a comment and before the \ that
// continues a command line, and a reference or an expression ($VAR,
// $(command), ${{ secrets.X }}, a TOML inline table, a YAML tag, alias or
// flow collection) is taken as one word, the first, as any value elsewhere
// on a line is. An nsswitch.conf passwd line, which names lookup services,
// is left as it is.
func TestRedactLineValuesStop(t *testing.T) {
	const v = "correct horse battery staple"
	for in, want := range map[string]string{
		"password = " + v + " # rotated":                                                 "password = [REDACTED] # rotated",
		"password = " + v + " ; rotated":                                                 "password = [REDACTED] ; rotated",
		"password = " + v + " // rotated":                                                "password = [REDACTED] // rotated",
		"password = " + v + " /* rotated */":                                             "password = [REDACTED] /* rotated */",
		"PASSWORD=" + v + " \\":                                                          "PASSWORD=[REDACTED] \\",
		"password=123               ; default is no password":                            "password=[REDACTED]               ; default is no password",
		"password_length = 8;\t/* Change this to match config */":                        "password_length = [REDACTED]\t/* Change this to match config */",
		"  --db-password=magento \\":                                                     "  --db-password=[REDACTED] \\",
		"  --credential-file-override=${KOKORO_GFILE_DIR}/kokoro.json \\":                "  --credential-file-override=[REDACTED] \\",
		"export GITHUB_ACCESS_TOKEN=$(cat $KOKORO_KEYSTORE_DIR/73713_github-key)":        "export GITHUB_ACCESS_TOKEN=[REDACTED] $KOKORO_KEYSTORE_DIR/73713_github-key)",
		"    token: ${{ secrets.CODECOV_TOKEN }}":                                        "    token: [REDACTED] secrets.CODECOV_TOKEN }}",
		`cargo-credential = { version = "0.4.0", path = "credential/cargo-credential" }`: `cargo-credential = [REDACTED] version = "0.4.0", path = "credential/cargo-credential" }`,
		"api_password: !secret http_password":                                            "api_password: [REDACTED] http_password",
		"password: *db_password extra":                                                   "password: [REDACTED] extra",
		"credentials: [aws, gcp]":                                                        "credentials: [REDACTED] gcp]",
		"password: " + v + " \\":                                                         "password: [REDACTED] \\",
	} {
		if got, n := redact(in); got != want || n != 1 {
			t.Errorf("redact(%q) = %q (%d), want %q", in, got, n, want)
		}
	}
	for _, in := range []string{
		"passwd:         files systemd",
		"passwd:     compat\n",
		"passwd: files sss [NOTFOUND=return] ldap\r\n",
		"passwd_compat: nis",
	} {
		if got, n := redact(in); got != in || n != 0 {
			t.Errorf("redact(%q) = %q (%d), changed an nsswitch line", in, got, n)
		}
	}
	// A passwd line that is not one is redacted.
	for in, want := range map[string]string{
		"passwd: " + v:                        "passwd: [REDACTED]",
		"passwd: files hunter2":               "passwd: [REDACTED]",
		"  passwd: $6$rounds=4096$saltsalt$h": "  passwd: [REDACTED]",
		"x passwd: files systemd":             "x passwd: [REDACTED] systemd",
	} {
		if got, n := redact(in); got != want || n != 1 {
			t.Errorf("redact(%q) = %q (%d), want %q", in, got, n, want)
		}
	}
}

// A mysql command line that gives -p more than once has its first and its
// last redacted; a later command on the line keeps its arguments.
func TestRedactMySQLPasswords(t *testing.T) {
	for in, want := range map[string]string{
		"mysql -uroot -pFirst1x db -pSecond2y":         "mysql -uroot -p[REDACTED] db -p[REDACTED]",
		"mysqldump -p'a b' -pLast9 shop > shop.sql":    "mysqldump -p[REDACTED] -p[REDACTED] shop > shop.sql",
		"mysql -pFirst1x db; ls -pfoo":                 "mysql -p[REDACTED] db; ls -pfoo",
		"mysql -uroot -pOnly1 db":                      "mysql -uroot -p[REDACTED] db",
		"mariadb-dump -h db -pOne1 x | mysql -pTwo2 y": "mariadb-dump -h db -p[REDACTED] x | mysql -p[REDACTED] y",
	} {
		got, _ := redact(in)
		if got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// An Authorization header's credentials are redacted whatever the scheme,
// all of a scheme's parameters, and with no scheme. Only the header's value
// goes: what follows it on a log line stays.
func TestRedactAuthorizationSchemes(t *testing.T) {
	for in, want := range map[string]string{
		"Authorization: ApiKey dGhpc2lzc2VjcmV0":                "Authorization: ApiKey [REDACTED]",
		"Authorization: Bot MTk4NjIy.Cl2FMQ.ZnCjm1XVW7vRze4b7":  "Authorization: Bot [REDACTED]",
		"Authorization: SSWS 00abcdefghijklmnopqrstuvwxyz":      "Authorization: SSWS [REDACTED]",
		"Authorization: Negotiate YIIGhgYGKwYBBQUCoIIGejCCBnag": "Authorization: Negotiate [REDACTED]",
		"proxy-authorization: NTLM TlRMTVNTUAABAAAA":            "proxy-authorization: NTLM [REDACTED]",
		`Authorization: Digest username="u", realm="My Realm", nonce="abc", uri="/", response="6629fae49393a05397450978507c4ef1"`:                                                               "Authorization: Digest [REDACTED]",
		"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe": "Authorization: AWS4-HMAC-SHA256 [REDACTED]",
		"Authorization: abcdef123456":                     "Authorization: [REDACTED]",
		"> Authorization: Bearer abc.def x-request-id: 7": "> Authorization: Bearer [REDACTED] x-request-id: 7",
	} {
		if got, n := redact(in); got != want || n == 0 {
			t.Errorf("redact(%q) = %q (%d), want %q", in, got, n, want)
		}
	}
	// A header name on a line of its own takes nothing from the next line.
	if in := "Authorization:\nnext line"; func() bool { got, n := redact(in); return got != in || n != 0 }() {
		t.Errorf("redact(%q) changed it", in)
	}
}

// An Authorization header's credentials are redacted where YAML puts the
// value on the line after the name, indented or as a list item, where HTTP
// folds the header onto the next line, before or after the scheme, quoted
// in single quotes, and with the name quoted, as JSON and a Python dict
// write it; read_file, run and job_poll show none of it. A YAML section
// named authorization keeps its keys, a scheme that ends its line takes
// neither the next key of a map nor the next line of a comment, and code
// that adds a token to a bare scheme keeps it.
func TestRedactAuthorizationAcrossLines(t *testing.T) {
	const cred = "c2VydmljZS1hY2NvdW50OnMzY3IzdC1wYXNzd29yZA"
	for in, want := range map[string]string{
		"http:\n  headers:\n    Authorization:\n      Bearer " + cred + "\n":                     "http:\n  headers:\n    Authorization:\n      Bearer [REDACTED]\n",
		"GET /api HTTP/1.1\r\nAuthorization:\r\n Basic " + cred + "\r\n\r\n":                     "GET /api HTTP/1.1\r\nAuthorization:\r\n Basic [REDACTED]\r\n\r\n",
		"Proxy-Authorization: Basic\r\n\t" + cred + "\r\n":                                       "Proxy-Authorization: [REDACTED]\r\n\t[REDACTED]\r\n",
		"headers:\n  Authorization: Bearer\n  Content-Type: application/json\n":                  "headers:\n  Authorization: [REDACTED]\n  Content-Type: application/json\n",
		"\t//  1. Authorization: Bearer\n\t//  2. x-goog-iap-jwt-assertion\n":                    "\t//  1. Authorization: [REDACTED]\n\t//  2. x-goog-iap-jwt-assertion\n",
		"      Authorization:\n      - Bearer " + cred + "\n":                                    "      Authorization:\n      - Bearer [REDACTED]\n",
		"Authorization: >-\n  Bearer " + cred + "\n":                                             "Authorization: >-\n  Bearer [REDACTED]\n",
		"Authorization:\n  '" + cred + "'\n":                                                     "Authorization:\n  [REDACTED]\n",
		"Authorization: 'Bearer " + cred + "'\n":                                                 "Authorization: [REDACTED]\n",
		"{ Authorization: 'Bearer " + cred + "' }":                                               "{ Authorization: [REDACTED] }",
		`"Authorization": "Bearer ` + cred + `",`:                                                `"Authorization": [REDACTED],`,
		`{"authorization":"Basic ` + cred + `"}`:                                                 `{"authorization":[REDACTED]}`,
		`headers = {'Proxy-Authorization': 'Bearer ` + cred + `'}`:                               `headers = {'Proxy-Authorization': [REDACTED]}`,
		"\t\tauthorization: \"Basic " + cred + "\",\n\t\tcontentType:   \"application/json\",\n": "\t\tauthorization: [REDACTED],\n\t\tcontentType:   \"application/json\",\n",
	} {
		got, n := redact(in)
		if got != want || n != strings.Count(want, "[REDACTED]") {
			t.Errorf("redact(%q) = %q (%d), want %q", in, got, n, want)
		}
		run, _ := cutOutput([]byte(in), 256<<10)
		polls, _ := pollPages(t, []byte(in), 256<<10)
		page := readPage([]byte(in), 0, 1<<20).Content
		for name, got := range map[string]string{"run": run, "job_poll": polls, "read_file": page} {
			if strings.Contains(got, cred) {
				t.Errorf("%s shows the credential of %q: %q", name, in, got)
			}
		}
	}
	for _, in := range []string{
		"authorization:\n  mode: Webhook\n  webhook:\n    cacheAuthorizedTTL: 5m0s\n",
		"authorization:\n  authorizers:\n  - type: Webhook\n",
		"Authorization:\nnext line\n",
		`req.headers = {"Authorization": "Bearer " + token}`,
		`headers = {"Authorization": f"Bearer {token}"}`,
	} {
		if got, n := redact(in); got != in || n != 0 {
			t.Errorf("redact(%q) = %q (%d), changed it", in, got, n)
		}
	}
}

// Tools that take a password as an argument have it redacted: keytool and
// jarsigner, PuTTY's tools, ipmitool, 7-Zip, zip and unzip, FreeRDP, nmcli,
// aws configure set and the Oracle tools' user/password. Their other
// arguments are left as they are.
func TestRedactToolPasswordArguments(t *testing.T) {
	const pw = "Hunter2xyzzyQ7"
	for _, c := range []struct {
		in string
		n  int
	}{
		{"keytool -importkeystore -srcstorepass " + pw + " -deststorepass " + pw, 2},
		{"keytool -genkey -keystore k.jks -storepass " + pw + " -keypass " + pw, 2},
		{"keytool -storepasswd -new " + pw + " -keystore k.jks", 1},
		{"jarsigner -storepass " + pw + " app.jar alias", 1},
		{"plink -ssh -pw " + pw + " admin@host", 1},
		{"pscp -pw " + pw + " f admin@host:", 1},
		{"ipmitool -I lanplus -H bmc -U admin -P " + pw + " power status", 1},
		{"7z x -p" + pw + " backup.7z", 1},
		{"zip -P " + pw + " out.zip f", 1},
		{"unzip -P " + pw + " out.zip", 1},
		{"xfreerdp /u:admin /p:" + pw + " /v:host", 1},
		{"nmcli dev wifi connect HomeNet password " + pw, 1},
		{"nmcli con modify home wifi-sec.psk " + pw, 1},
		{"aws configure set aws_secret_access_key " + pw, 1},
		{"aws configure set default.aws_session_token " + pw + " --profile p", 1},
		{"sqlplus system/" + pw + "@ORCL", 1},
		{"expdp system/" + pw + "@db schemas=x", 1},
		{"sqlldr userid=scott/" + pw + " control=load.ctl", 1},
		{"psexec \\\\host -u admin -p " + pw + " cmd", 1},
		{"crackmapexec smb 10.0.0.5 -u admin -p " + pw, 1},
		{"htpasswd -b .htpasswd alice " + pw, 1},
		{"htpasswd -nbB alice " + pw + "\r\n", 1},
		{"net use \\\\fs\\share " + pw + " /user:CORP\\alice", 1},
	} {
		if got, n := redact(c.in); strings.Contains(got, pw) || n != c.n {
			t.Errorf("redact(%q) = %q (%d, want %d)", c.in, got, n, c.n)
		}
	}
	for _, s := range []string{
		"7z x backup.7z -o/tmp", "zip -r out.zip dir", "sqlplus / as sysdba", "sqlplus -s @/opt/scripts/report.sql",
		"aws configure set region eu-west-1", "nmcli dev wifi list", "ipmitool -I lanplus -H bmc power status",
		"keytool -list -keystore k.jks", "htpasswd -D .htpasswd alice", "net use x: \\\\fs\\share /persistent:no",
		"net use \\\\fs\\share * /user:alice",
	} {
		if got, n := redact(s); got != s || n != 0 {
			t.Errorf("redact(%q) changed ordinary text: %q (%d)", s, got, n)
		}
	}
}

// A YAML secret whose value carries a tag or an anchor is redacted after
// it, in every way the model reads it: Ansible's !unsafe for a password
// that holds {{, !!str for a numeric one, !!binary, and an &anchor. A tag
// that makes the value a reference to a secret leaves the name readable.
func TestRedactTaggedYAMLValues(t *testing.T) {
	for in, secret := range map[string]string{
		"ansible_become_password: !unsafe 'S3cr{{t-Pw'\n":                                "S3cr{{t-Pw",
		"mypassword: !unsafe 234%234{435lkj{{lkjsdf\n":                                   "234%234{435lkj{{lkjsdf",
		"  db_password: !!str 0123456789\n":                                              "0123456789",
		"api_token: !!binary aHVudGVyMi1zM2NyM3Q=\n":                                     "aHVudGVyMi1zM2NyM3Q=",
		"x-db: &dbpass\n  POSTGRES_PASSWORD: &pw Hunter2Secret\n  OTHER_PASSWORD: *pw\n": "Hunter2Secret",
	} {
		got, n := redact(in)
		run, _ := cutOutput([]byte(in), 256<<10)
		polls, _ := pollPages(t, []byte(in), 256<<10)
		page := readPage([]byte(in), 0, 1<<20).Content
		for name, out := range map[string]string{"redact": got, "run": run, "job_poll": polls, "read_file": page} {
			if strings.Contains(out, secret) {
				t.Errorf("%s shows %q (redacted %d): %q", name, secret, n, out)
			}
		}
	}
	// A reference names no secret: the name it gives stays readable.
	for in, name := range map[string]string{"db_password: !secret db_password\n": "db_password\n",
		"MasterUserPassword: !Ref DBPassword\n": "DBPassword\n"} {
		if got, _ := redact(in); !strings.HasSuffix(got, " "+name) {
			t.Errorf("the reference's name was redacted: %q", got)
		}
	}
}

// Go's print of an http.Header, map[Authorization:[Bearer x]], hides the
// credential.
func TestRedactAuthorizationInGoHeader(t *testing.T) {
	in := "headers: map[Accept:[*/*] Authorization:[Bearer abc123tokXYZ987] User-Agent:[go]]\n"
	if got, _ := redact(in); strings.Contains(got, "abc123tokXYZ987") {
		t.Errorf("the token shows: %q", got)
	}
}

package creds

import (
	"encoding/hex"
	"strings"
)

// keysFromKeychainDump returns the account ("acct") of every generic-password
// item for service in the output of `security dump-keychain` (run without
// -d, so it carries attributes only, never secrets). Order follows the dump.
//
// Attribute lines look like
//
//	"acct"<blob>="dev:refresh_token"
//	"acct"<blob>=0x6163C3A96D65...  "ac\303\251me..."   (non-printable: hex)
//	"acct"<blob>=<NULL>
func keysFromKeychainDump(dump, service string) []string {
	var out []string
	var class, svce, acct string
	var hasSvce, hasAcct bool
	flush := func() {
		if class == "genp" && hasSvce && hasAcct && svce == service {
			out = append(out, acct)
		}
		class, svce, acct, hasSvce, hasAcct = "", "", "", false, false
	}
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "keychain:"):
			flush()
		case strings.HasPrefix(line, "class:"):
			class = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "class:")), `"`)
		case strings.HasPrefix(line, `"svce"<blob>=`):
			svce, hasSvce = dumpBlobValue(strings.TrimPrefix(line, `"svce"<blob>=`))
		case strings.HasPrefix(line, `"acct"<blob>=`):
			acct, hasAcct = dumpBlobValue(strings.TrimPrefix(line, `"acct"<blob>=`))
		}
	}
	flush()
	return out
}

// dumpBlobValue decodes the right-hand side of a dump-keychain blob attribute.
func dumpBlobValue(v string) (string, bool) {
	if strings.HasPrefix(v, "0x") {
		h := v[2:]
		if i := strings.IndexAny(h, " \t"); i >= 0 {
			h = h[:i]
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1], true
	}
	return "", false // <NULL> or unrecognized
}

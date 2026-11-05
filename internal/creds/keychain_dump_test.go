package creds

import (
	"reflect"
	"testing"
)

// Trimmed real output of `security dump-keychain` (no -d: attributes only,
// never secrets).
const sampleDump = `keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="presswrench/dev:refresh_token"
    "acct"<blob>="dev:refresh_token"
    "desc"<blob>="PressWrench session"
    "svce"<blob>="presswrench"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="refresh_token"
    "svce"<blob>="someone-else"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "svce"<blob>="presswrench"
    "acct"<blob>="access_token"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=0x6163C3A96D653A726566726573685F746F6B656E  "ac\303\251me:refresh_token"
    "svce"<blob>="presswrench"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="refresh_token"
    "srvr"<blob>="presswrench"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=<NULL>
    "svce"<blob>="presswrench"
`

func TestKeysFromKeychainDump(t *testing.T) {
	got := keysFromKeychainDump(sampleDump, "presswrench")
	want := []string{"dev:refresh_token", "access_token", "acéme:refresh_token"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keysFromKeychainDump = %q, want %q", got, want)
	}
	if accts := accountsFromKeys(got); !reflect.DeepEqual(accts, []string{"acéme", "dev"}) {
		t.Errorf("accounts = %q", accts)
	}
}

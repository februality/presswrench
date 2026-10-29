package clients

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONOfficialEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	doc := `{
	  "mcpServers": {
	    "pressable": {"type": "http", "url": "https://mcp.pressable.com"},
	    "presswrench": {"command": "/bin/presswrench", "args": ["serve"], "env": {"X": "mcp.pressable.com"}},
	    "other": {"command": "node", "args": ["x.js"]}
	  },
	  "projects": {
	    "/Users/me/site": {"mcpServers": {"pressable-remote": {"command": "npx", "args": ["mcp-remote", "https://mcp.pressable.com/"]}}}
	  }
	}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := jsonPatcher{configPath: path, jsonPath: "mcpServers.presswrench"}.officialEntries()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "pressable,pressable-remote (project /Users/me/site)" {
		t.Errorf("got %q", got)
	}
}

func TestJSONOfficialEntries_Missing(t *testing.T) {
	got, err := jsonPatcher{configPath: filepath.Join(t.TempDir(), "none.json"), jsonPath: "servers.presswrench"}.officialEntries()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestTOMLOfficialEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	doc := "[mcp_servers.pressable]\nurl = \"https://mcp.pressable.com\"\n\n[mcp_servers.presswrench]\ncommand = \"/bin/presswrench\"\n\n[mcp_servers.other]\ncommand = \"x\"\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := tomlPatcher{configPath: path, tablePath: []string{"mcp_servers", "presswrench"}}.officialEntries()
	if err != nil || strings.Join(got, ",") != "pressable" {
		t.Fatalf("got %v, %v", got, err)
	}
}

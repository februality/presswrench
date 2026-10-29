package clients

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/tidwall/gjson"
)

// OfficialHost is Pressable's hosted MCP server. When an AI tool has it
// configured alongside presswrench, the model can call Pressable directly
// and skip presswrench's read-only mode and operation blocklist.
const OfficialHost = "mcp.pressable.com"

// OfficialEntry is a config entry, in some client, that connects to
// Pressable's hosted MCP server.
type OfficialEntry struct {
	Client string // display name, e.g. "Claude Code"
	Path   string // config file
	Name   string // entry name, with " (project <dir>)" for project-scoped entries
}

// FindOfficial scans every client config for entries that reach
// OfficialHost — directly by URL, or through a wrapper such as mcp-remote
// whose arguments contain it. Unreadable or malformed configs are skipped.
func FindOfficial() []OfficialEntry {
	var out []OfficialEntry
	for _, p := range All("") {
		names, err := p.OfficialEntries()
		if err != nil {
			continue
		}
		_, path, _ := p.Detect()
		for _, n := range names {
			out = append(out, OfficialEntry{Client: p.DisplayName(), Path: path, Name: n})
		}
	}
	return out
}

// officialEntries finds OfficialHost entries in any object named like the
// patcher's parent key ("mcpServers" / "servers") at any depth, which
// covers Claude Code's project-scoped servers under projects.<dir>.
func (p jsonPatcher) officialEntries() ([]string, error) {
	b, err := os.ReadFile(p.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	if !gjson.ValidBytes(b) {
		return nil, fmt.Errorf("%w: %s", ErrMalformedConfig, p.configPath)
	}
	parent, _ := parentPath(p.jsonPath)
	var out []string
	var walk func(node gjson.Result, owner string, depth int)
	walk = func(node gjson.Result, owner string, depth int) {
		node.ForEach(func(k, v gjson.Result) bool {
			if !v.IsObject() {
				return true
			}
			if k.String() != parent {
				walk(v, k.String(), depth+1)
				return true
			}
			v.ForEach(func(name, entry gjson.Result) bool {
				if _, ours := parseEntryName(name.String()); !ours && strings.Contains(entry.Raw, OfficialHost) {
					label := name.String()
					if depth > 0 {
						label += " (project " + owner + ")"
					}
					out = append(out, label)
				}
				return true
			})
			return true
		})
	}
	walk(gjson.ParseBytes(b), "", 0)
	return out, nil
}

func (p tomlPatcher) officialEntries() ([]string, error) {
	if len(p.tablePath) == 0 {
		return nil, nil
	}
	b, err := os.ReadFile(p.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	root := map[string]any{}
	if err := toml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedTOML, p.configPath, err)
	}
	cur := root
	for _, key := range p.tablePath[:len(p.tablePath)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil, nil
		}
		cur = next
	}
	var out []string
	for name, entry := range cur {
		if _, ours := parseEntryName(name); !ours && strings.Contains(fmt.Sprint(entry), OfficialHost) {
			out = append(out, name)
		}
	}
	sortAccounts(out)
	return out, nil
}

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Operation is what we need to know about a Pressable operation to apply
// local policy: its name and Pressable's own behavior annotations.
type Operation struct {
	Name        string
	ReadOnly    bool
	Destructive bool
}

// Describer caches describe_tool lookups. Operation metadata is static for
// the life of the process.
type Describer struct {
	c     *Client
	mu    sync.Mutex
	cache map[string]*Operation
}

func NewDescriber(c *Client) *Describer {
	return &Describer{c: c, cache: map[string]*Operation{}}
}

// Describe returns the operation's annotations. Unknown operations are an
// error (the gateway reports them as a tool error).
func (d *Describer) Describe(ctx context.Context, name string) (*Operation, error) {
	d.mu.Lock()
	if op, ok := d.cache[name]; ok {
		d.mu.Unlock()
		return op, nil
	}
	d.mu.Unlock()

	res, err := d.c.CallTool(ctx, "describe_tool", map[string]any{"tool_name": name})
	if err != nil {
		return nil, err
	}
	text := ResultText(res)
	if res.IsError {
		return nil, fmt.Errorf("describe %s: %s", name, strings.TrimSpace(text))
	}
	op, err := parseOperation(name, text)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.cache[name] = op
	d.mu.Unlock()
	return op, nil
}

func parseOperation(name, text string) (*Operation, error) {
	var raw struct {
		Name        string `json:"name"`
		Annotations struct {
			ReadOnlyHint    *bool `json:"readOnlyHint"`
			DestructiveHint *bool `json:"destructiveHint"`
		} `json:"annotations"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("describe %s: could not parse definition: %w", name, err)
	}
	if raw.Name != "" && raw.Name != name {
		return nil, fmt.Errorf("describe %s: gateway returned the definition of %q", name, raw.Name)
	}
	op := &Operation{Name: name}
	// Absent hints are treated conservatively: not read-only, destructive.
	if raw.Annotations.ReadOnlyHint != nil {
		op.ReadOnly = *raw.Annotations.ReadOnlyHint
	}
	op.Destructive = true
	if raw.Annotations.DestructiveHint != nil {
		op.Destructive = *raw.Annotations.DestructiveHint
	}
	return op, nil
}

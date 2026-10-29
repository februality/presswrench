package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/februality/presswrench/internal/auth"
)

// RegisterGatewayTools registers the pass-through to Pressable's MCP
// gateway. Results come back exactly as Pressable returned them; the only
// local logic is policy (blocklist, read-only) applied before
// pressable_execute forwards a call.
func RegisterGatewayTools(s *server.MCPServer, d *Deps) {
	s.AddTool(toolDiscover(d), handleDiscover(d))
	s.AddTool(toolDescribe(), handleDescribe(d))
	s.AddTool(toolExecute(d), handleExecute(d))
}

func toolDiscover(d *Deps) mcp.Tool {
	desc := "List the Pressable platform operations available to the signed-in user (about 200: sites, domains, DNS, SSL, backups, restores, plugins, themes, logs, collaborators, caching, metrics, WordPress users, and more). Returns each operation's name, title, summary and category. Pass `query` to filter by substring (e.g. \"backup\", \"dns\", \"plugin\"). Next: pressable_describe for parameters, then pressable_execute."
	if d.Cfg.ReadOnly {
		desc += " Read-only mode is on: only operations Pressable marks read-only can be executed."
	}
	return mcp.NewTool("pressable_discover",
		mcp.WithDescription(desc),
		mcp.WithString("query", mcp.Description("Optional case-insensitive substring to filter operations by name, title, or summary")),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
	)
}

func toolDescribe() mcp.Tool {
	return mcp.NewTool("pressable_describe",
		mcp.WithDescription("Return one Pressable operation's full definition: description, input schema (parameters, types, required fields), and behavior annotations (readOnlyHint, destructiveHint). Call before pressable_execute."),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Exact operation name from pressable_discover (e.g. \"list_sites\")")),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
	)
}

func toolExecute(d *Deps) mcp.Tool {
	desc := "Run a Pressable platform operation with the given parameters, as the signed-in user. Pressable enforces the user's site access and collaborator roles and logs the action. Find operations with pressable_discover and their parameters with pressable_describe first."
	if d.Cfg.ReadOnly {
		desc += " Read-only mode is on: operations Pressable does not mark read-only are refused."
	}
	if len(d.Cfg.BlockedOperations) > 0 {
		desc += " Blocked locally: " + strings.Join(d.Cfg.BlockedOperations, ", ") + "."
	}
	return mcp.NewTool("pressable_execute",
		mcp.WithDescription(desc),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Exact operation name from pressable_discover")),
		mcp.WithObject("parameters", mcp.Description("The operation's parameters, matching its input schema from pressable_describe")),
		mcp.WithDestructiveHintAnnotation(true),
	)
}

func handleDiscover(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := map[string]any{}
		if q := req.GetString("query", ""); q != "" {
			args["query"] = q
		}
		return passThrough(d.Gateway.CallTool(ctx, "discover_tools", args))
	}
}

func handleDescribe(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := req.RequireString("tool_name")
		if err != nil {
			return errResult(err)
		}
		return passThrough(d.Gateway.CallTool(ctx, "describe_tool", map[string]any{"tool_name": name}))
	}
}

func handleExecute(d *Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := req.RequireString("tool_name")
		if err != nil {
			return errResult(err)
		}
		name = strings.TrimSpace(name)
		params := map[string]any{}
		if raw, ok := req.GetArguments()["parameters"]; ok && raw != nil {
			switch v := raw.(type) {
			case map[string]any:
				params = v
			case string:
				// Some clients send nested objects as JSON strings.
				if err := json.Unmarshal([]byte(v), &params); err != nil {
					return errResult(fmt.Errorf("parameters must be an object: %w", err))
				}
			default:
				return errResult(errors.New("parameters must be an object"))
			}
		}
		if err := checkPolicy(ctx, d, name); err != nil {
			return errResult(err)
		}
		return passThrough(d.Gateway.CallTool(ctx, "execute_tool", map[string]any{"tool_name": name, "parameters": params}))
	}
}

// checkPolicy applies the local blocklist and read-only mode. Pressable's
// own permission checks still apply afterwards.
func checkPolicy(ctx context.Context, d *Deps, name string) error {
	for _, b := range d.Cfg.BlockedOperations {
		if strings.EqualFold(b, name) {
			return fmt.Errorf("Operation %q is blocked by local policy (PRESSWRENCH_BLOCKED_OPERATIONS). Do it in the MyPressable dashboard, or remove it from the blocklist with `presswrench install --blocked-operations ...`", name)
		}
	}
	if !d.Cfg.ReadOnly {
		return nil
	}
	op, err := d.Describer.Describe(ctx, name)
	if err != nil {
		return fmt.Errorf("read-only mode: could not verify that %q is read-only: %w", name, err)
	}
	if !op.ReadOnly {
		return fmt.Errorf("Operation %q is not read-only and read-only mode is on (PRESSWRENCH_READ_ONLY)", name)
	}
	return nil
}

// passThrough returns a gateway result unchanged, turning transport errors
// into tool errors.
func passThrough(res *mcp.CallToolResult, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return errResult(err)
	}
	return res, nil
}

func jsonText(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(b)), nil
}

// errResult reports err to the model as a tool error. A missing session
// gets an actionable message instead of a bare sentinel.
func errResult(err error) (*mcp.CallToolResult, error) {
	if errors.Is(err, auth.ErrLoginRequired) {
		return mcp.NewToolResultError("Not signed in to Pressable (or the session expired). Ask the user to run `presswrench login` in a terminal, then retry."), nil
	}
	return mcp.NewToolResultError(err.Error()), nil
}

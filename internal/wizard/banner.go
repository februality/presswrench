package wizard

import (
	"fmt"
	"io"

	"github.com/februality/presswrench/internal/mcpserver"
)

// printBanner writes a brief welcome to w.
func printBanner(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  PressWrench — Setup")
	fmt.Fprintln(w, "  ───────────────────")
	fmt.Fprintf(w, "  v%s\n", mcpserver.ServerVersion)
	fmt.Fprintln(w)
}

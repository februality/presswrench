package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/februality/presswrench/internal/cli"
	"github.com/februality/presswrench/internal/ui"
)

func main() {
	if err := cli.Execute(); err != nil {
		if !ui.IsReported(err) && !errors.Is(err, ui.ErrCancelled) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(ui.ExitCode(err))
	}
}

// Package main is the entry point for lastpass-mcp.
package main

import (
	"os"

	"lastpass-mcp/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

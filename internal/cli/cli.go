// Package cli provides the command-line interface for lastpass-mcp.
package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	mcpserver "lastpass-mcp/internal/mcp"
)

// MCP server command flags
var (
	mcpPort        int
	mcpHost        string
	mcpBaseURL     string
	mcpEnvironment string
	mcpDataDir     string
)

// rootCmd is the root command for the CLI.
var rootCmd = &cobra.Command{
	Use:   "lastpass-mcp",
	Short: "LastPass MCP Server",
	Long:  "LastPass MCP Server provides vault management tools via the Model Context Protocol.",
}

// mcpCmd starts the MCP server.
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the MCP server",
	Long: `Start the MCP (Model Context Protocol) server for remote access.

The MCP server enables AI assistants to manage LastPass vault entries remotely
using the standard MCP protocol over HTTP Streamable transport.

Available tools:
  lastpass_login   Authenticate to LastPass
  lastpass_logout  Terminate the LastPass session
  lastpass_search  Search vault entries by regex
  lastpass_show    Show full entry details by ID
  lastpass_create  Create a new vault entry
  lastpass_update  Update an existing vault entry

Authentication:
  The server implements OAuth 2.1 with Dynamic Client Registration.
  The authorize endpoint presents a LastPass login page where the user
  enters their email and master password. On success, a Bearer token
  is issued that maps to the user's LastPass session.

  OAuth endpoints:
  /.well-known/oauth-protected-resource
  /.well-known/oauth-authorization-server
  /oauth/register
  /oauth/authorize
  /oauth/token`,
	Example: `  # Start MCP server on default port (8080)
  lastpass-mcp mcp

  # Start on custom port
  lastpass-mcp mcp --port 3000

  # Start on all interfaces
  lastpass-mcp mcp --host 0.0.0.0 --port 8080`,
	RunE: runMCP,
}

func init() {
	mcpCmd.Flags().IntVarP(&mcpPort, "port", "p", 8080, "Port to listen on")
	mcpCmd.Flags().StringVarP(&mcpHost, "host", "H", "localhost", "Host to bind to")
	mcpCmd.Flags().StringVar(&mcpBaseURL, "base-url", "", "Base URL for OAuth callbacks (e.g., https://lastpass.mcp.scm-platform.org)")
	mcpCmd.Flags().StringVar(&mcpEnvironment, "environment", "", "Environment (dev, stg, prd)")
	mcpCmd.Flags().StringVar(&mcpDataDir, "data-dir", "", "Directory for persistent state (OAuth clients, tokens)")

	rootCmd.AddCommand(mcpCmd)
}

func runMCP(cmd *cobra.Command, args []string) error {
	host := mcpHost
	if host == "localhost" {
		if envHost := os.Getenv("HOST"); envHost != "" {
			host = envHost
		}
	}

	port := mcpPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}

	baseURL := mcpBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("BASE_URL")
	}

	environment := mcpEnvironment
	if environment == "" {
		environment = os.Getenv("ENVIRONMENT")
	}

	dataDir := mcpDataDir
	if dataDir == "" {
		dataDir = os.Getenv("DATA_DIR")
	}

	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", host, port)
	}

	cfg := &mcpserver.Config{
		Host:        host,
		Port:        port,
		BaseURL:     baseURL,
		Environment: environment,
		DataDir:     dataDir,
	}

	server := mcpserver.NewServer(cfg)
	return server.Run(context.Background())
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

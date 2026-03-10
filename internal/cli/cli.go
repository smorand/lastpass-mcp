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
	mcpPort           int
	mcpHost           string
	mcpBaseURL        string
	mcpSecretName     string
	mcpSecretProject  string
	mcpCredentialFile string
	mcpEnvironment    string
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

  # Production deployment with Secret Manager
  lastpass-mcp mcp --secret-project "my-gcp-project" --secret-name "oauth-credentials"

  # Start on all interfaces
  lastpass-mcp mcp --host 0.0.0.0 --port 8080`,
	RunE: runMCP,
}

func init() {
	// Setup mcp command flags
	mcpCmd.Flags().IntVarP(&mcpPort, "port", "p", 8080, "Port to listen on")
	mcpCmd.Flags().StringVarP(&mcpHost, "host", "H", "localhost", "Host to bind to")
	mcpCmd.Flags().StringVar(&mcpBaseURL, "base-url", "", "Base URL for OAuth callbacks (e.g., https://lastpass.mcp.scm-platform.org)")
	mcpCmd.Flags().StringVar(&mcpSecretName, "secret-name", "", "Secret Manager secret name for OAuth credentials")
	mcpCmd.Flags().StringVar(&mcpSecretProject, "secret-project", "", "GCP project for Secret Manager")
	mcpCmd.Flags().StringVar(&mcpCredentialFile, "credential-file", "", "Local OAuth credential file path (fallback)")
	mcpCmd.Flags().StringVar(&mcpEnvironment, "environment", "", "Environment (dev, stg, prd)")

	rootCmd.AddCommand(mcpCmd)
}

func runMCP(cmd *cobra.Command, args []string) error {
	// Determine host: use flag value, then HOST env var, then default
	host := mcpHost
	if host == "localhost" {
		if envHost := os.Getenv("HOST"); envHost != "" {
			host = envHost
		}
	}

	// Determine port: use flag value, then PORT env var, then default
	port := mcpPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}

	// Get Secret Manager project from env if not set via flag
	secretProject := mcpSecretProject
	if secretProject == "" {
		secretProject = os.Getenv("SECRET_PROJECT")
		if secretProject == "" {
			secretProject = os.Getenv("PROJECT_ID")
		}
	}

	// Get Secret Manager secret name from env if not set via flag
	secretName := mcpSecretName
	if secretName == "" {
		secretName = os.Getenv("SECRET_NAME")
	}

	// Get base URL from env if not set via flag
	baseURL := mcpBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("BASE_URL")
	}

	// Get environment from env if not set via flag
	environment := mcpEnvironment
	if environment == "" {
		environment = os.Getenv("ENVIRONMENT")
	}

	// Build default base URL if not set
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", host, port)
	}

	// Get state bucket from env
	stateBucket := os.Getenv("STATE_BUCKET")

	// Get KMS key name from env
	kmsKeyName := os.Getenv("KMS_KEY_NAME")

	// Create MCP server configuration
	cfg := &mcpserver.Config{
		Host:           host,
		Port:           port,
		BaseURL:        baseURL,
		SecretName:     secretName,
		SecretProject:  secretProject,
		CredentialFile: mcpCredentialFile,
		Environment:    environment,
		StateBucket:    stateBucket,
		KmsKeyName:     kmsKeyName,
	}

	server := mcpserver.NewServer(cfg)
	return server.Run(context.Background())
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

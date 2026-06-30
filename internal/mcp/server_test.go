package mcp_test

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/rostradamus/klaws/internal/detector"
	"github.com/rostradamus/klaws/internal/law"
	devmcp "github.com/rostradamus/klaws/internal/mcp"
	"github.com/rostradamus/klaws/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupServer(t *testing.T) *server.MCPServer {
	t.Helper()

	reg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
		detector.NewMarketingConsentDetector(),
		detector.NewFinancialDataDetector(),
		detector.NewRetentionDetector(),
	)
	svc := scanner.NewService(reg)
	lawReg, err := law.NewRegistry("")
	require.NoError(t, err)

	srv := devmcp.NewServer(svc, reg, lawReg)
	require.NotNil(t, srv, "server should be created successfully")
	return srv
}

func TestMCP_ServerCreation(t *testing.T) {
	setupServer(t)
}

func TestMCP_RegistersExpectedTools(t *testing.T) {
	tools := setupServer(t).ListTools()

	for _, name := range []string{"scan_directory", "scan_file", "list_detectors", "get_law_reference"} {
		assert.Contains(t, tools, name, "tool %q should be registered", name)
	}
	assert.Len(t, tools, 4, "exactly four tools should be registered")
}

func TestMCP_ToolMetadataIsDescriptive(t *testing.T) {
	tools := setupServer(t).ListTools()

	for name, st := range tools {
		tool := st.Tool

		// Descriptions are the model's only cue for when to call a tool, so
		// guard against regressing back to terse one-liners.
		assert.Greater(t, len(tool.Description), 80,
			"tool %q should have a substantive description", name)

		// Every tool is read-only and should carry a human-readable title.
		require.NotNil(t, tool.Annotations.ReadOnlyHint, "tool %q missing read-only hint", name)
		assert.True(t, *tool.Annotations.ReadOnlyHint, "tool %q should be read-only", name)
		assert.NotEmpty(t, tool.Annotations.Title, "tool %q should have a title", name)

		// The "not legal advice" contract must not be undermined by absolutist
		// language in any tool-facing string. Mirrors the full forbidden set the
		// legal-mapper guidance enforces.
		for _, forbidden := range []string{"violation", "illegal", "non-compliant", "you must", "fails to comply"} {
			assert.NotContains(t, tool.Description, forbidden,
				"tool %q description should avoid %q", name, forbidden)
		}
	}
}

func TestMCP_LawReferenceReachesExternalSource(t *testing.T) {
	tools := setupServer(t).ListTools()

	// get_law_reference can fetch from law.go.kr, so it should be flagged as
	// open-world; the local-only scan tools should not.
	require.NotNil(t, tools["get_law_reference"].Tool.Annotations.OpenWorldHint)
	assert.True(t, *tools["get_law_reference"].Tool.Annotations.OpenWorldHint)

	require.NotNil(t, tools["scan_file"].Tool.Annotations.OpenWorldHint)
	assert.False(t, *tools["scan_file"].Tool.Annotations.OpenWorldHint)
}

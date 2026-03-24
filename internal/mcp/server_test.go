package mcp_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	devmcp "github.com/rostradamus/klaws/internal/mcp"
	"github.com/rostradamus/klaws/internal/law"
	"github.com/rostradamus/klaws/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupServer(t *testing.T) {
	t.Helper()

	reg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
	)
	svc := scanner.NewService(reg)
	lawReg, err := law.NewRegistry("")
	require.NoError(t, err)

	srv := devmcp.NewServer(svc, reg, lawReg)
	assert.NotNil(t, srv, "server should be created successfully")
}

func TestMCP_ServerCreation(t *testing.T) {
	setupServer(t)
}

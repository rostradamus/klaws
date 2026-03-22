package mcp_test

import (
	"testing"

	"github.com/rostradamus/dev-lawyer/internal/detector"
	devmcp "github.com/rostradamus/dev-lawyer/internal/mcp"
	"github.com/rostradamus/dev-lawyer/internal/law"
	"github.com/rostradamus/dev-lawyer/internal/scanner"
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

package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rostradamus/klaws/internal/detector"
	"github.com/rostradamus/klaws/internal/law"
	"github.com/rostradamus/klaws/internal/scanner"
)

func NewServer(svc *scanner.ScannerService, detReg *detector.Registry, lawReg *law.Registry) *server.MCPServer {
	s := server.NewMCPServer(
		"klaws",
		"0.1.0",
		server.WithToolCapabilities(false),
	)

	addScanDirectoryTool(s, svc)
	addScanFileTool(s, svc)
	addListDetectorsTool(s, detReg)
	addGetLawReferenceTool(s, lawReg)

	return s
}

func addScanDirectoryTool(s *server.MCPServer, svc *scanner.ScannerService) {
	tool := mcp.NewTool("scan_directory",
		mcp.WithDescription("Scan a directory for possible Korean compliance risks"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the directory to scan"),
		),
		mcp.WithString("file_pattern",
			mcp.Description("Glob pattern for files to scan (default: *.java)"),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, err := req.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError("path is required"), nil
		}
		pattern := req.GetString("file_pattern", "*.java")

		rpt, err := svc.ScanDirectory(path, pattern)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
		}

		data, err := json.MarshalIndent(rpt, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("formatting failed: %v", err)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})
}

func addScanFileTool(s *server.MCPServer, svc *scanner.ScannerService) {
	tool := mcp.NewTool("scan_file",
		mcp.WithDescription("Scan a single file for possible Korean compliance risks"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the file to scan"),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, err := req.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError("path is required"), nil
		}

		rpt, err := svc.ScanFile(path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
		}

		data, err := json.MarshalIndent(rpt, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("formatting failed: %v", err)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})
}

func addListDetectorsTool(s *server.MCPServer, detReg *detector.Registry) {
	tool := mcp.NewTool("list_detectors",
		mcp.WithDescription("List all available compliance risk detectors"),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		infos := detReg.Info()
		data, err := json.MarshalIndent(infos, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("formatting failed: %v", err)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})
}

func addGetLawReferenceTool(s *server.MCPServer, lawReg *law.Registry) {
	tool := mcp.NewTool("get_law_reference",
		mcp.WithDescription("Look up a Korean law provision by ID"),
		mcp.WithString("law_id",
			mcp.Required(),
			mcp.Description("Law provision ID (e.g., PIPA-15, PIPA-29)"),
		),
		mcp.WithBoolean("live",
			mcp.Description("Fetch full text from law.go.kr (default: false)"),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		lawID, err := req.RequireString("law_id")
		if err != nil {
			return mcp.NewToolResultError("law_id is required"), nil
		}

		live := req.GetBool("live", false)

		var l law.Law
		if live {
			l, err = lawReg.LookupLive(lawID)
		} else {
			l, err = lawReg.Lookup(lawID)
		}

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("law lookup failed: %v", err)), nil
		}

		data, err := json.MarshalIndent(l, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("formatting failed: %v", err)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})
}

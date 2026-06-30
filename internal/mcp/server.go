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

// Built from interpreted string segments with explicit "\n\n" paragraph
// breaks, so no incidental source indentation leaks into the text sent to MCP
// clients.
const serverInstructions = "klaws scans source code for *possible* Korean compliance risks and maps each " +
	"finding to one or more specific legal provisions. It covers four laws: PIPA (개인정보 보호법), " +
	"the Network Act (정보통신망법), the Credit Information Act (신용정보법), and the " +
	"E-Commerce Act (전자상거래법).\n\n" +
	"Use scan_directory to review a whole project or folder, and scan_file for a single " +
	"file (for example, the one currently being edited). Use list_detectors to see what " +
	"each detector looks for, and get_law_reference to expand a provision ID returned in a " +
	"finding's related_laws.\n\n" +
	"Important: klaws surfaces possible risks for human review only. It does not provide " +
	"legal advice and does not reach definitive legal conclusions. Present each finding as " +
	"something that \"may require review\", cite the related provision(s), and recommend " +
	"consulting qualified legal counsel for definitive guidance."

func NewServer(svc *scanner.ScannerService, detReg *detector.Registry, lawReg *law.Registry) *server.MCPServer {
	s := server.NewMCPServer(
		"klaws",
		"0.1.1",
		server.WithToolCapabilities(false),
		server.WithInstructions(serverInstructions),
	)

	addScanDirectoryTool(s, svc)
	addScanFileTool(s, svc)
	addListDetectorsTool(s, detReg)
	addGetLawReferenceTool(s, lawReg)

	return s
}

func addScanDirectoryTool(s *server.MCPServer, svc *scanner.ScannerService) {
	tool := mcp.NewTool("scan_directory",
		mcp.WithDescription(
			"Scan all matching files in a directory tree for possible Korean compliance "+
				"risks across PIPA, the Network Act, the Credit Information Act, and the "+
				"E-Commerce Act. Returns a JSON report where each finding has a detector_id, "+
				"risk_level (HIGH or MEDIUM), file_path, line_number, snippet, a hedged "+
				"message, and related_laws (provision IDs you can pass to get_law_reference). "+
				"Findings are possible risks for review, not legal conclusions. Use this for a "+
				"whole project or folder; use scan_file for a single file.",
		),
		mcp.WithTitleAnnotation("Scan directory for compliance risks"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the directory to scan (e.g. /Users/me/project/src)."),
		),
		mcp.WithString("file_pattern",
			mcp.Description(
				"Glob pattern selecting which files to scan. Defaults to *.java. "+
					"Examples: \"*.java\", \"*.kt\". Detectors target Java/Kotlin-style source.",
			),
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
		mcp.WithDescription(
			"Scan a single source file for possible Korean compliance risks and return the "+
				"same JSON report shape as scan_directory. Use this to check one file (for "+
				"example, the file currently being edited); use scan_directory to review a "+
				"whole project. Findings are possible risks for review, not legal conclusions.",
		),
		mcp.WithTitleAnnotation("Scan file for compliance risks"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the file to scan (e.g. /Users/me/project/src/UserService.java)."),
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
		mcp.WithDescription(
			"List every available compliance risk detector with its id, name, description "+
				"(the code pattern it looks for), and the related_laws it maps to. Use this to "+
				"explain what klaws checks for, or to see which risks to expect before "+
				"scanning. Takes no arguments.",
		),
		mcp.WithTitleAnnotation("List detectors"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
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
		mcp.WithDescription(
			"Look up a bundled Korean law provision by ID and return its Korean and English "+
				"names, a plain-language summary, the source URL on law.go.kr, a risk level, "+
				"and (when available) the full Korean article text. Typically used to expand a "+
				"related_laws ID returned by a scan. This is reference material, not legal advice.",
		),
		mcp.WithTitleAnnotation("Get Korean law reference"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("law_id",
			mcp.Required(),
			mcp.Description(
				"Bundled provision ID. Examples by law: PIPA-15, PIPA-29 (개인정보 보호법); "+
					"NIA-22, NIA-50 (정보통신망법); CIA-19 (신용정보법); ECA-6 (전자상거래법).",
			),
		),
		mcp.WithBoolean("live",
			mcp.Description(
				"If true, fetch the latest full text from law.go.kr (requires network access). "+
					"If false (default), use the text bundled in the binary.",
			),
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

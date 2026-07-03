package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/rostradamus/klaws/internal/detector"
	"github.com/rostradamus/klaws/internal/law"
	devmcp "github.com/rostradamus/klaws/internal/mcp"
	"github.com/rostradamus/klaws/internal/report"
	"github.com/rostradamus/klaws/internal/scanner"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

var (
	pattern   string
	format    string
	liveFetch bool
	lawsPath  string
	httpAddr  string
	authToken string
	scanRoot  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "klaws",
		Short:   "Scan codebases for possible Korean compliance risks",
		Long:    "klaws identifies potential compliance risks in codebases and maps them to Korean law provisions. This tool does not provide legal advice.",
		Version: version,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a file or directory for compliance risks",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}
	scanCmd.Flags().StringVarP(&pattern, "pattern", "p", "*.java", "File glob pattern")
	scanCmd.Flags().StringVarP(&format, "format", "f", "json", "Output format (json or text)")

	detectorsCmd := &cobra.Command{
		Use:   "detectors",
		Short: "List available compliance risk detectors",
		RunE:  runDetectors,
	}

	lawCmd := &cobra.Command{
		Use:   "law [id]",
		Short: "Look up a Korean law provision by ID",
		Args:  cobra.ExactArgs(1),
		RunE:  runLaw,
	}
	lawCmd.Flags().BoolVar(&liveFetch, "live", false, "Fetch full text from law.go.kr")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start as an MCP server (stdio by default, or Streamable HTTP with --http)",
		RunE:  runServe,
	}
	serveCmd.Flags().StringVar(&httpAddr, "http", "", "Serve over Streamable HTTP on this address (e.g. :8080) instead of stdio")
	serveCmd.Flags().StringVar(&authToken, "auth-token", "", "Require this bearer token on --http requests (or set KLAWS_AUTH_TOKEN)")
	serveCmd.Flags().StringVar(&scanRoot, "scan-root", "", "Restrict scan_directory/scan_file to paths within this directory")

	rootCmd.PersistentFlags().StringVar(&lawsPath, "laws", "", "Path to laws.yaml (default: embedded)")

	rootCmd.AddCommand(scanCmd, detectorsCmd, lawCmd, serveCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildDeps() (*scanner.ScannerService, *detector.Registry, *law.Registry, error) {
	detReg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
		detector.NewMarketingConsentDetector(),
		detector.NewFinancialDataDetector(),
		detector.NewRetentionDetector(),
	)
	svc := scanner.NewService(detReg)

	// Pass lawsPath directly — empty string uses go:embed fallback
	lawReg, err := law.NewRegistry(lawsPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading laws: %w", err)
	}

	return svc, detReg, lawReg, nil
}

func runScan(cmd *cobra.Command, args []string) error {
	svc, _, _, err := buildDeps()
	if err != nil {
		return err
	}

	path := args[0]
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	var rpt report.Report
	if info.IsDir() {
		rpt, err = svc.ScanDirectory(path, pattern)
	} else {
		rpt, err = svc.ScanFile(path)
	}
	if err != nil {
		return err
	}

	switch format {
	case "text":
		fmt.Print(report.FormatText(rpt))
	case "json":
		data, err := report.FormatJSON(rpt)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		return fmt.Errorf("invalid format %q: must be \"json\" or \"text\"", format)
	}
	return nil
}

func runDetectors(cmd *cobra.Command, args []string) error {
	_, detReg, _, err := buildDeps()
	if err != nil {
		return err
	}

	infos := detReg.Info()
	data, err := json.MarshalIndent(infos, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func runLaw(cmd *cobra.Command, args []string) error {
	_, _, lawReg, err := buildDeps()
	if err != nil {
		return err
	}

	lawID := args[0]

	var l law.Law
	if liveFetch {
		l, err = lawReg.LookupLive(lawID)
	} else {
		l, err = lawReg.Lookup(lawID)
	}
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func runServe(cmd *cobra.Command, args []string) error {
	svc, detReg, lawReg, err := buildDeps()
	if err != nil {
		return err
	}

	srv := devmcp.NewServer(svc, detReg, lawReg, devmcp.WithScanRoot(scanRoot))

	if httpAddr == "" {
		return mcpserver.ServeStdio(srv)
	}

	token := authToken
	if token == "" {
		token = os.Getenv("KLAWS_AUTH_TOKEN")
	}

	httpSrv := mcpserver.NewStreamableHTTPServer(srv)
	var handler http.Handler = httpSrv
	authNote := " — WARNING: no --auth-token set; do not expose to untrusted networks"
	if token != "" {
		handler = devmcp.BearerAuth(token, httpSrv)
		authNote = " (bearer auth required)"
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	fmt.Fprintf(os.Stderr, "klaws MCP server listening on %s/mcp (Streamable HTTP)%s\n", httpAddr, authNote)

	// ReadHeaderTimeout and IdleTimeout bound slow/idle connections
	// (Slowloris). WriteTimeout is intentionally omitted: the Streamable HTTP
	// transport keeps server-to-client streams open, and a write deadline would
	// cut them off.
	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return httpServer.ListenAndServe()
}

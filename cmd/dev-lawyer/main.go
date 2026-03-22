package main

import (
	"encoding/json"
	"fmt"
	"os"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/rostradamus/dev-lawyer/internal/detector"
	"github.com/rostradamus/dev-lawyer/internal/law"
	devmcp "github.com/rostradamus/dev-lawyer/internal/mcp"
	"github.com/rostradamus/dev-lawyer/internal/report"
	"github.com/rostradamus/dev-lawyer/internal/scanner"
)

var (
	pattern   string
	format    string
	liveFetch bool
	lawsPath  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dev-lawyer",
		Short: "Scan codebases for possible Korean compliance risks",
		Long:  "dev-lawyer identifies potential compliance risks in codebases and maps them to Korean law provisions. This tool does not provide legal advice.",
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
		Short: "Start as MCP server (stdio transport)",
		RunE:  runServe,
	}

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
	default:
		data, err := report.FormatJSON(rpt)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
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

	srv := devmcp.NewServer(svc, detReg, lawReg)
	return mcpserver.ServeStdio(srv)
}

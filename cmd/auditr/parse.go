package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/parsers"
	"github.com/vaibhaw-/AuditR/internal/auditr/runner"
)

var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Convert raw DB audit logs → NDJSON events",
	RunE:  runParse,
}

var (
	flagDB         string
	flagInput      string
	flagOutput     string
	flagRejectFile string
	flagFollow     bool
	flagEmitRaw    bool
)

func init() {
	parseCmd.Flags().StringVar(&flagDB, "db", "", "db type: postgres|mysql (required)")
	parseCmd.Flags().StringVar(&flagInput, "input", "", "input file (default stdin)")
	parseCmd.Flags().StringVar(&flagOutput, "output", "", "output file (default stdout)")
	parseCmd.Flags().StringVar(&flagRejectFile, "reject-file", "", "file to store rejected/skipped log entries")
	parseCmd.Flags().BoolVar(&flagFollow, "follow", false, "follow (tail) input stream")
	parseCmd.Flags().BoolVar(&flagEmitRaw, "emit-raw", false, "include raw_query in output")
	parseCmd.MarkFlagRequired("db")
}

func runParse(cmd *cobra.Command, args []string) error {
	cfg := config.Get()

	// Override config with command line flags
	if flagRejectFile != "" {
		cfg.Output.RejectFile = flagRejectFile
	}

	// Input reader
	var in io.Reader
	if flagInput == "" {
		in = os.Stdin
	} else {
		f, err := os.Open(flagInput)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer f.Close()
		in = f
	}

	// Output writer
	var out io.Writer
	if flagOutput == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		out = f
	}

	// Build parser via factory (pluggable)
	factory := parsers.NewFactory()
	p, err := factory.NewParser(flagDB, parsers.ParserOptions{
		EmitRaw: flagEmitRaw,
		Config:  cfg, // pass config for parser-specific settings
	})
	if err != nil {
		return fmt.Errorf("create parser: %w", err)
	}

	ctx := context.Background()

	// Use shared runner
	if err := runner.RunParse(ctx, p, in, out, flagDB, cfg); err != nil {
		return err
	}

	return nil
}

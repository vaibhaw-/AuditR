package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
	"github.com/vaibhaw-/AuditR/internal/auditr/parsers"
)

var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Convert raw DB audit logs → NDJSON events",
	RunE:  runParse,
}

var (
	flagDB      string
	flagInput   string
	flagOutput  string
	flagFollow  bool
	flagEmitRaw bool
)

func init() {
	parseCmd.Flags().StringVar(&flagDB, "db", "", "db type: postgres|mysql (required)")
	parseCmd.Flags().StringVar(&flagInput, "input", "", "input file (default stdin)")
	parseCmd.Flags().StringVar(&flagOutput, "output", "", "output file (default stdout)")
	parseCmd.Flags().BoolVar(&flagFollow, "follow", false, "follow (tail) input stream")
	parseCmd.Flags().BoolVar(&flagEmitRaw, "emit-raw", false, "include raw_query in output")
	parseCmd.MarkFlagRequired("db")
}

func runParse(cmd *cobra.Command, args []string) error {
	log := logger.L()
	cfg := config.Get()

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
	scanner := bufio.NewScanner(in)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		line := scanner.Text()

		evt, err := p.ParseLine(ctx, line)
		if err != nil {
			if errors.Is(err, parsers.ErrSkipLine) {
				// Emit a structured ERROR event instead of dropping the line
				raw := line // copy to avoid pointer to loop variable
				errEvt := &parsers.Event{
					EventID:   uuid.NewString(),
					Timestamp: "", // could parse timestamp if partially available
					DBSystem:  flagDB,
					DBUser:    nil,
					DBName:    nil,
					QueryType: "ERROR",
					RawQuery:  &raw,
				}
				if err := enc.Encode(errEvt); err != nil {
					log.Errorw("encode error event", "err", err.Error())
				}
				continue
			}
			// Fatal parse error — stop the run
			return fmt.Errorf("parse error: %w", err)
		}

		// evt == nil means skip silently (shouldn’t happen in our design, but just in case)
		if evt == nil {
			continue
		}

		if err := enc.Encode(evt); err != nil {
			log.Errorw("encode event", "err", err.Error())
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan input: %w", err)
	}

	return nil
}

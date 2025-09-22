package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
	"github.com/vaibhaw-/AuditR/internal/auditr/parsers"
	"go.uber.org/zap"
)

type RunSummary struct {
	Timestamp     string `json:"timestamp"`
	Input         string `json:"input"`
	Output        string `json:"output"`
	RejectFile    string `json:"reject_file,omitempty"`
	RawCount      int    `json:"raw_count"`
	ParsedCount   int    `json:"parsed_count"`
	RejectedCount int    `json:"rejected_count"`
}

// createErrorEvent creates a standardized error event
func createErrorEvent(queryType string, line string, db string) *parsers.Event {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	raw := line
	return &parsers.Event{
		EventID:   uuid.NewString(),
		Timestamp: ts,
		DBSystem:  db,
		QueryType: queryType,
		RawQuery:  &raw,
	}
}

// eventEncoder wraps event encoding operations
type eventEncoder struct {
	enc    *json.Encoder
	reject *json.Encoder
	log    *zap.SugaredLogger
	db     string
}

func newEventEncoder(out io.Writer, reject io.Writer, db string) *eventEncoder {
	var rejectEnc *json.Encoder
	if reject != nil {
		rejectEnc = json.NewEncoder(reject)
	}
	return &eventEncoder{
		enc:    json.NewEncoder(out),
		reject: rejectEnc,
		log:    logger.L(),
		db:     db,
	}
}

func (e *eventEncoder) encodeEvent(evt *parsers.Event) error {
	if err := e.enc.Encode(evt); err != nil {
		errEvt := createErrorEvent("PARSE_ERROR", *evt.RawQuery, e.db)
		_ = e.enc.Encode(errEvt)
		e.log.Errorw("encode event", "err", err.Error())
		return fmt.Errorf("encode event: %w", err)
	}
	return nil
}

func (e *eventEncoder) encodeReject(line string) error {
	if e.reject == nil {
		return nil
	}
	skipEvt := createErrorEvent("SKIP", line, e.db)
	if err := e.reject.Encode(skipEvt); err != nil {
		e.log.Errorw("encode skip event", "err", err.Error())
		return fmt.Errorf("encode skip event: %w", err)
	}
	return nil
}

func appendRunLog(path string, summary RunSummary) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(summary)
}

// openRejectFile opens the reject file if configured, returns nil if not configured
func openRejectFile(cfg *config.Config) (io.WriteCloser, error) {
	if cfg == nil || cfg.Output.RejectFile == "" {
		return nil, nil
	}
	return os.OpenFile(cfg.Output.RejectFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

// RunParse is the core loop for parsing audit logs.
// It is factored out from the Cobra command so it can be unit tested.
// parseResult tracks parsing statistics
type parseResult struct {
	rawCount      int
	parsedCount   int
	rejectedCount int
}

// processLine handles a single line of input.
// It attempts to parse the line and returns:
// - true if the line was successfully parsed and encoded
// - false if the line was skipped or resulted in an error event
// - error if a fatal error occurred
func processLine(ctx context.Context, line string, p parsers.Parser, enc *eventEncoder) (bool, error) {
	log := logger.L()
	log.Debugw("processing line", "length", len(line))

	evt, err := p.ParseLine(ctx, line)
	if err != nil {
		if errors.Is(err, parsers.ErrSkipLine) {
			log.Debugw("skipping line", "reason", "parser requested skip")
			if err := enc.encodeReject(line); err != nil {
				log.Errorw("failed to encode reject event", "err", err.Error())
				return false, err
			}
			return false, nil // skipped but not fatal
		}
		// Fatal parse error
		log.Errorw("parse error",
			"err", err.Error(),
			"line", line)
		errEvt := createErrorEvent("PARSE_ERROR", line, enc.db)
		_ = enc.enc.Encode(errEvt)
		return false, fmt.Errorf("parse error: %w", err)
	}

	if evt == nil {
		// Unexpected nil → emit error event
		log.Warnw("parser returned nil event", "line", line)
		errEvt := createErrorEvent("PARSE_ERROR", line, enc.db)
		if err := enc.enc.Encode(errEvt); err != nil {
			log.Errorw("failed to encode error event", "err", err.Error())
			return false, fmt.Errorf("encode nil event: %w", err)
		}
		return false, nil
	}

	log.Debugw("successfully parsed event",
		"event_id", evt.EventID,
		"query_type", evt.QueryType,
		"db_user", evt.DBUser)

	if err := enc.encodeEvent(evt); err != nil {
		log.Errorw("failed to encode event",
			"err", err.Error(),
			"event_id", evt.EventID)
		return false, err
	}

	return true, nil
}

// RunParse is the core loop for parsing audit logs.
// It reads input line by line, parses each line into an event, and writes
// the events to the appropriate output (main output or reject file).
// The function also maintains statistics about processed lines and can
// write a summary to a run log if configured.
func RunParse(ctx context.Context, p parsers.Parser, in io.Reader, out io.Writer, db string, cfg *config.Config) error {
	log := logger.L()
	// Log run configuration
	logConfig := map[string]interface{}{
		"db_type": db,
	}
	if cfg != nil {
		logConfig["input"] = cfg.Input.FilePath
		logConfig["output"] = cfg.Output.Dir
		logConfig["reject_file"] = cfg.Output.RejectFile
	}
	log.Infow("starting parse run", "config", logConfig)

	// Setup reject file if configured
	var rejectFile io.WriteCloser
	if cfg != nil {
		var err error
		rejectFile, err = openRejectFile(cfg)
		if err != nil {
			log.Errorw("failed to open reject file",
				"path", cfg.Output.RejectFile,
				"err", err.Error())
			return fmt.Errorf("open reject file: %w", err)
		}
		if rejectFile != nil {
			log.Debugw("opened reject file", "path", cfg.Output.RejectFile)
			defer rejectFile.Close()
		}
	}

	// Setup encoders
	enc := newEventEncoder(out, rejectFile, db)
	log.Debugw("initialized event encoder",
		"has_reject_file", rejectFile != nil)

	// Process input
	scanner := bufio.NewScanner(in)
	result := parseResult{}
	startTime := time.Now()

	log.Debugw("starting input processing")
	for scanner.Scan() {
		result.rawCount++
		if result.rawCount%1000 == 0 {
			log.Infow("processing progress",
				"lines_processed", result.rawCount,
				"parsed_count", result.parsedCount,
				"rejected_count", result.rejectedCount)
		}

		line := scanner.Text()
		parsed, err := processLine(ctx, line, p, enc)
		if err != nil {
			log.Errorw("failed to process line",
				"line_number", result.rawCount,
				"err", err.Error())
			return err
		}

		if parsed {
			result.parsedCount++
		} else {
			result.rejectedCount++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorw("scanner error", "err", err.Error())
		return fmt.Errorf("scan input: %w", err)
	}

	// Write run summary if configured
	if cfg != nil && cfg.Logging.RunLog != "" {
		summary := RunSummary{
			Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
			Input:         cfg.Input.FilePath,
			Output:        cfg.Output.Dir,
			RejectFile:    cfg.Output.RejectFile,
			RawCount:      result.rawCount,
			ParsedCount:   result.parsedCount,
			RejectedCount: result.rejectedCount,
		}
		if err := appendRunLog(cfg.Logging.RunLog, summary); err != nil {
			log.Errorw("failed to write run log",
				"path", cfg.Logging.RunLog,
				"err", err.Error())
		} else {
			log.Debugw("wrote run summary", "path", cfg.Logging.RunLog)
		}
	}

	duration := time.Since(startTime)
	log.Infow("completed parse run",
		"duration", duration,
		"lines_processed", result.rawCount,
		"parsed_count", result.parsedCount,
		"rejected_count", result.rejectedCount,
		"lines_per_second", float64(result.rawCount)/duration.Seconds())

	return nil
}

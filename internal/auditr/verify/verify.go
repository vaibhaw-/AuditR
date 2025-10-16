package verify

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

type VerifyArgs struct {
	InputFile      string
	OutputFile     string
	Checkpoint     bool
	PrivateKeyPath string
	PublicKeyPath  string
	SummaryOnly    bool
	Detailed       bool
	CheckpointPath string // for verify mode, if provided
}

// RunVerifyPhase is the main entry point for the verify phase orchestration
func RunVerifyPhase(cfg *config.Config, args VerifyArgs) error {
	log := logger.L()
	start := time.Now().UTC()
	mode := "hash"
	if args.PublicKeyPath != "" {
		mode = "verify"
	}
	log.Infow("verify phase start", "mode", mode, "input", args.InputFile, "output", args.OutputFile)

	// IO setup
	var in *os.File
	var err error
	if args.InputFile == "" {
		in = os.Stdin
	} else {
		in, err = os.Open(args.InputFile)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer in.Close()
	}

	var out *os.File
	if mode == "hash" {
		if args.OutputFile == "" {
			out = os.Stdout
		} else {
			out, err = os.Create(args.OutputFile)
			if err != nil {
				return fmt.Errorf("create output: %w", err)
			}
			defer out.Close()
		}
	}

	summary := VerifySummary{
		Phase:     "verify",
		Mode:      mode,
		InputFile: args.InputFile,
		StartTime: start.Format(time.RFC3339),
	}
	if args.OutputFile != "" {
		summary.OutputFile = args.OutputFile
	}

	if mode == "hash" {
		state, _ := LoadState(cfg.Hashing.StateFile)
		log.Debugw("state loaded", "index", state.LastChainIndex, "head", state.LastHeadHash)
		newState, processed, err := ComputeChain(in, out, state)
		if err != nil {
			return err
		}
		summary.EventsProcessed = processed
		// write checkpoint if requested via flag or configured interval == file_end
		if args.Checkpoint || cfg.Hashing.CheckpointInterval == "file_end" {
			key := args.PrivateKeyPath
			if key == "" {
				key = cfg.Signing.PrivateKeyPath
			}
			path, err := WriteCheckpoint(cfg.Hashing.CheckpointDir, newState.LastChainIndex, newState.LastHeadHash, key)
			if err != nil {
				return err
			}
			log.Infow("checkpoint written", "path", path, "index", newState.LastChainIndex)
			summary.CheckpointPath = path
		}
		if err := SaveState(cfg.Hashing.StateFile, newState); err != nil {
			return err
		}
		log.Debugw("state saved", "index", newState.LastChainIndex, "head", newState.LastHeadHash)
		summary.Status = "sealed"
	} else {
		tampered, headHash, processed, err := VerifyChain(in)
		if err != nil {
			return err
		}
		summary.EventsProcessed = processed
		summary.TamperedEvents = tampered
		verified := true
		if args.CheckpointPath != "" && args.PublicKeyPath != "" {
			v, err := VerifyCheckpoint(args.CheckpointPath, args.PublicKeyPath, headHash)
			if err != nil {
				return err
			}
			verified = v
			summary.CheckpointsVerified = v
			log.Infow("checkpoint verify", "path", args.CheckpointPath, "result", v)
		}
		summary.Status = "pass"
		if len(tampered) > 0 || !verified {
			summary.Status = "fail"
		}
		_ = headHash
	}

	end := time.Now().UTC()
	summary.EndTime = end.Format(time.RFC3339)
	// duration_ms added when detailed flag or development enabled
	durationMs := end.Sub(start).Seconds() * 1000
	if cfg != nil && cfg.Logging.RunLog != "" {
		// In summary mode, slim down the summary; in detailed include duration_ms
		if args.SummaryOnly {
			// keep core fields only
			summary.TamperedEvents = nil
		}
		if args.Detailed || cfg.Logging.Development {
			// marshal through a map to include duration_ms without changing struct
			// but since we only have struct, we enrich via wrapper map
			// Build a map from summary
			m := map[string]interface{}{
				"phase":                summary.Phase,
				"mode":                 summary.Mode,
				"input_file":           summary.InputFile,
				"output_file":          summary.OutputFile,
				"events_processed":     summary.EventsProcessed,
				"tampered_events":      summary.TamperedEvents,
				"checkpoints_verified": summary.CheckpointsVerified,
				"checkpoint_path":      summary.CheckpointPath,
				"status":               summary.Status,
				"start_time":           summary.StartTime,
				"end_time":             summary.EndTime,
				"duration_ms":          durationMs,
			}
			if err := appendVerifyRunLogMap(cfg.Logging.RunLog, m); err != nil {
				log.Warnw("failed to write run log summary", "err", err.Error())
			}
		} else {
			if err := appendVerifyRunLog(cfg.Logging.RunLog, summary); err != nil {
				log.Warnw("failed to write run log summary", "err", err.Error())
			}
		}
	}
	// Console output behavior for summary/detailed
	if args.SummaryOnly {
		// minimal single line
		fmt.Printf("verify %s: %s (events=%d)\n", mode, summary.Status, summary.EventsProcessed)
	} else if args.Detailed {
		fmt.Printf("verify %s: %s (events=%d, duration_ms=%.2f, checkpoint=%s, tampered=%d)\n", mode, summary.Status, summary.EventsProcessed, durationMs, summary.CheckpointPath, len(summary.TamperedEvents))
	}
	log.Infow("verify phase end", "status", summary.Status, "events", summary.EventsProcessed)
	return nil
}

func appendVerifyRunLog(path string, summary VerifySummary) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	if err := enc.Encode(summary); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

func appendVerifyRunLogMap(path string, m map[string]interface{}) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	if err := enc.Encode(m); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

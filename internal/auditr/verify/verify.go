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

// VerifyArgs contains the command-line arguments and configuration for the verify phase
//
// This structure encapsulates all the parameters needed to run the verify phase,
// including file paths, cryptographic keys, and output formatting options.
//
// Fields:
//   - InputFile: Path to input NDJSON file (empty means stdin)
//   - OutputFile: Path to output file (empty means stdout for hash mode)
//   - Checkpoint: Whether to create a checkpoint after processing
//   - PrivateKeyPath: Path to ECDSA private key for signing checkpoints
//   - PublicKeyPath: Path to ECDSA public key for verifying checkpoints
//   - SummaryOnly: Whether to output minimal summary information
//   - Detailed: Whether to output detailed information including timing
//   - CheckpointPath: Path to checkpoint file for verification (verify mode only)
type VerifyArgs struct {
	InputFile      string // Input NDJSON file path (empty = stdin)
	OutputFile     string // Output file path (empty = stdout for hash mode)
	Checkpoint     bool   // Whether to create checkpoint after processing
	PrivateKeyPath string // ECDSA private key for signing
	PublicKeyPath  string // ECDSA public key for verification
	SummaryOnly    bool   // Minimal output mode
	Detailed       bool   // Detailed output mode with timing
	CheckpointPath string // Checkpoint file path (verify mode only)
}

// RunVerifyPhase is the main entry point for the verify phase orchestration
//
// This function coordinates the entire verify phase, which can operate in two modes:
// 1. "hash" mode: Computes hash chains for events and optionally creates checkpoints
// 2. "verify" mode: Verifies existing hash chains and optionally validates checkpoints
//
// The function handles:
// - Input/output file management (stdin/stdout support)
// - Hash chain computation or verification
// - Checkpoint creation and verification
// - State persistence for resumable processing
// - Comprehensive logging and summary generation
// - Multiple output formats (summary, detailed, JSON logs)
//
// Args:
//   - cfg: Application configuration containing paths and settings
//   - args: Command-line arguments and options
//
// Returns:
//   - Error if any step fails, nil on success
func RunVerifyPhase(cfg *config.Config, args VerifyArgs) error {
	log := logger.L()
	start := time.Now().UTC()

	// Determine operation mode based on presence of public key
	mode := "hash"
	if args.PublicKeyPath != "" {
		mode = "verify"
	}
	log.Infow("verify phase start", "mode", mode, "input", args.InputFile, "output", args.OutputFile)

	// Set up input file (stdin if no file specified)
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

	// Set up output file (only needed for hash mode, stdout if no file specified)
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

	// Initialize summary structure for logging and reporting
	summary := VerifySummary{
		Phase:     "verify",
		Mode:      mode,
		InputFile: args.InputFile,
		StartTime: start.Format(time.RFC3339),
	}
	if args.OutputFile != "" {
		summary.OutputFile = args.OutputFile
	}

	// Execute the appropriate operation based on mode
	if mode == "hash" {
		// HASH MODE: Compute hash chains for events

		// Load previous state to resume chain from where it left off
		state, _ := LoadState(cfg.Hashing.StateFile)
		log.Debugw("state loaded", "index", state.LastChainIndex, "head", state.LastHeadHash)

		// Compute hash chain for all events in input
		newState, processed, err := ComputeChain(in, out, state)
		if err != nil {
			return err
		}
		summary.EventsProcessed = processed

		// Create checkpoint if requested (via flag or configured interval)
		if args.Checkpoint || cfg.Hashing.CheckpointInterval == "file_end" {
			// Determine which private key to use (command line takes precedence)
			key := args.PrivateKeyPath
			if key == "" {
				key = cfg.Signing.PrivateKeyPath
			}

			// Validate signing key presence and existence
			if key == "" {
				return fmt.Errorf("checkpoint requested but signing key not provided (use --private-key or signing.private_key_path)")
			}
			if _, err := os.Stat(key); err != nil {
				return fmt.Errorf("checkpoint requested but signing key not found: %s", key)
			}

			// Create and sign checkpoint
			path, err := WriteCheckpoint(cfg.Hashing.CheckpointDir, newState.LastChainIndex, newState.LastHeadHash, key)
			if err != nil {
				return err
			}
			log.Infow("checkpoint written", "path", path, "index", newState.LastChainIndex)
			summary.CheckpointPath = path
		}

		// Save updated state for next run
		if err := SaveState(cfg.Hashing.StateFile, newState); err != nil {
			return err
		}
		log.Debugw("state saved", "index", newState.LastChainIndex, "head", newState.LastHeadHash)
		summary.Status = "sealed"
	} else {
		// VERIFY MODE: Verify existing hash chains

		// Verify the hash chain integrity
		tampered, headHash, processed, err := VerifyChain(in)
		if err != nil {
			return err
		}
		summary.EventsProcessed = processed
		summary.TamperedEvents = tampered

		// Verify checkpoint if provided
		verified := true
		if args.CheckpointPath != "" || args.PublicKeyPath != "" {
			// Both public key and checkpoint path are required for verification
			if args.CheckpointPath == "" || args.PublicKeyPath == "" {
				return fmt.Errorf("checkpoint verification requires both --public-key and --checkpoint-path")
			}

			// Validate that both files exist
			if _, err := os.Stat(args.PublicKeyPath); err != nil {
				return fmt.Errorf("public key not found: %s", args.PublicKeyPath)
			}
			if _, err := os.Stat(args.CheckpointPath); err != nil {
				return fmt.Errorf("checkpoint file not found: %s", args.CheckpointPath)
			}

			// Verify the checkpoint signature and head hash match
			v, err := VerifyCheckpoint(args.CheckpointPath, args.PublicKeyPath, headHash)
			if err != nil {
				return err
			}
			verified = v
			summary.CheckpointsVerified = v
			log.Infow("checkpoint verify", "path", args.CheckpointPath, "result", v)
		}

		// Determine overall status based on chain and checkpoint verification
		summary.Status = "pass"
		if len(tampered) > 0 || !verified {
			summary.Status = "fail"
		}
		_ = headHash // Suppress unused variable warning
	}

	// Finalize timing and logging
	end := time.Now().UTC()
	summary.EndTime = end.Format(time.RFC3339)
	durationMs := end.Sub(start).Seconds() * 1000

	// Write run log if configured
	if cfg != nil && cfg.Logging.RunLog != "" {
		// In summary mode, remove detailed fields to reduce log size
		if args.SummaryOnly {
			summary.TamperedEvents = nil
		}

		// Choose logging format based on detail level
		if args.Detailed || cfg.Logging.Development {
			// Detailed mode: include duration_ms and all fields
			// Build enriched map with additional timing information
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
			// Standard mode: use struct-based logging
			if err := appendVerifyRunLog(cfg.Logging.RunLog, summary); err != nil {
				log.Warnw("failed to write run log summary", "err", err.Error())
			}
		}
	}
	// Generate console output based on verbosity level
	if args.SummaryOnly {
		// Minimal single-line output
		fmt.Printf("verify %s: %s (events=%d)\n", mode, summary.Status, summary.EventsProcessed)
	} else if args.Detailed {
		// Detailed output with timing and additional metrics
		fmt.Printf("verify %s: %s (events=%d, duration_ms=%.2f, checkpoint=%s, tampered=%d)\n",
			mode, summary.Status, summary.EventsProcessed, durationMs, summary.CheckpointPath, len(summary.TamperedEvents))
	}

	log.Infow("verify phase end", "status", summary.Status, "events", summary.EventsProcessed)
	return nil
}

// appendVerifyRunLog appends a verify summary to the run log file
//
// This function writes a VerifySummary struct as a JSON line to the specified
// run log file. The file is opened in append mode, so multiple runs can be
// logged to the same file without overwriting previous entries.
//
// Args:
//   - path: Path to the run log file
//   - summary: VerifySummary to append
//
// Returns:
//   - Error if writing fails, nil on success
func appendVerifyRunLog(path string, summary VerifySummary) error {
	// Open file in append mode (create if doesn't exist)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Use buffered writer for efficiency
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)

	// Encode summary as JSON line
	if err := enc.Encode(summary); err != nil {
		return err
	}

	// Ensure data is written to disk
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

// appendVerifyRunLogMap appends a map-based verify summary to the run log file
//
// This function is similar to appendVerifyRunLog but accepts a map instead of
// a struct. This allows for dynamic field inclusion (like duration_ms) without
// modifying the struct definition. Used for detailed logging mode.
//
// Args:
//   - path: Path to the run log file
//   - m: Map containing the summary data to append
//
// Returns:
//   - Error if writing fails, nil on success
func appendVerifyRunLogMap(path string, m map[string]interface{}) error {
	// Open file in append mode (create if doesn't exist)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Use buffered writer for efficiency
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)

	// Encode map as JSON line
	if err := enc.Encode(m); err != nil {
		return err
	}

	// Ensure data is written to disk
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

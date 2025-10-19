package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/verify"
)

var (
	verifyFlagInput        string
	verifyFlagOutput       string
	verifyFlagCheckpoint   bool
	verifyFlagPrivateKey   string
	verifyFlagPublicKey    string
	verifyFlagSummaryOnly  bool
	verifyFlagDetailed     bool
	verifyFlagCheckpointIn string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Compute or validate hash chain for NDJSON logs",
	Long: `Verify command operates in two modes:

Hash Mode (--output provided):
  Computes hash chains for events and optionally creates checkpoints
  Requires: --input, --output
  Optional: --checkpoint, --private-key

Verify Mode (no --output):
  Verifies existing hash chains and optionally validates checkpoints  
  Requires: --input
  Optional: --checkpoint-path, --public-key

Examples:
  # Hash mode: compute hash chains
  auditr verify --input events.jsonl --output hashed.jsonl --checkpoint --private-key key.pem
  
  # Verify mode: verify hash chains
  auditr verify --input hashed.jsonl
  
  # Verify mode: verify with checkpoint
  auditr verify --input hashed.jsonl --checkpoint-path checkpoint.json --public-key pub.pem`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate required arguments
		if verifyFlagInput == "" {
			return fmt.Errorf("--input is required")
		}

		// Determine mode based on --output presence
		if verifyFlagOutput != "" {
			// Hash mode: --output provided
			// No additional validation needed beyond --input
		} else {
			// Verify mode: no --output
			// --input is already validated above
		}

		cfg := config.Get()
		argsV := verify.VerifyArgs{
			InputFile:      verifyFlagInput,
			OutputFile:     verifyFlagOutput,
			Checkpoint:     verifyFlagCheckpoint,
			PrivateKeyPath: verifyFlagPrivateKey,
			PublicKeyPath:  verifyFlagPublicKey,
			SummaryOnly:    verifyFlagSummaryOnly,
			Detailed:       verifyFlagDetailed,
			CheckpointPath: verifyFlagCheckpointIn,
		}
		return verify.RunVerifyPhase(cfg, argsV)
	},
}

func init() {
	verifyCmd.Flags().StringVar(&verifyFlagInput, "input", "", "input NDJSON file (default stdin)")
	verifyCmd.Flags().StringVar(&verifyFlagOutput, "output", "", "output NDJSON file (default stdout; only in hash mode)")
	verifyCmd.Flags().BoolVar(&verifyFlagCheckpoint, "checkpoint", false, "write checkpoint JSON at end of run (hash mode)")
	verifyCmd.Flags().StringVar(&verifyFlagPrivateKey, "private-key", "", "private key PEM path for signing checkpoint (hash mode)")
	verifyCmd.Flags().StringVar(&verifyFlagPublicKey, "public-key", "", "public key PEM path for verifying checkpoint (verify mode)")
	verifyCmd.Flags().BoolVar(&verifyFlagSummaryOnly, "summary", false, "print summary only")
	verifyCmd.Flags().BoolVar(&verifyFlagDetailed, "detailed", false, "include per-event details where applicable")
	verifyCmd.Flags().StringVar(&verifyFlagCheckpointIn, "checkpoint-path", "", "checkpoint file to verify (verify mode)")

	// add to root in root.go's init
	if rootCmd == nil {
		// this should never happen; rootCmd is defined in root.go
		fmt.Println("warning: rootCmd not initialized")
	}
}

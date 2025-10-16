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
	RunE: func(cmd *cobra.Command, args []string) error {
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

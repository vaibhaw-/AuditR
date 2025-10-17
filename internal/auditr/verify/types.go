package verify

import "time"

// ChainState stores rolling head and index for multi-file continuity.
//
// This structure maintains the state of a hash chain across multiple processing
// runs, allowing the chain to be resumed from where it left off. This is essential
// for processing large datasets that may be split across multiple files or require
// multiple processing sessions.
//
// Fields:
//   - LastChainIndex: The index of the last processed event in the chain
//   - LastHeadHash: The hash of the last processed event (used as hash_prev for next event)
type ChainState struct {
	LastChainIndex int    `json:"last_chain_index"` // Position in the hash chain
	LastHeadHash   string `json:"last_head_hash"`   // Hash of the last event
}

// Checkpoint captures the chain head at a given chain index.
//
// A checkpoint is a cryptographically signed snapshot of the hash chain state
// at a specific point in time. It provides tamper-evident evidence of the
// chain's integrity and can be used to verify that the chain hasn't been
// modified since the checkpoint was created.
//
// This structure represents the payload that gets signed and persisted to disk.
// The signature is stored separately in the SignedCheckpoint wrapper.
//
// Fields:
//   - ChainIndex: Position in the hash chain when checkpoint was created
//   - HeadHash: Hash of the last event in the chain at checkpoint time
//   - CreatedAt: Timestamp when the checkpoint was created (UTC)
type Checkpoint struct {
	ChainIndex int       `json:"chain_index"` // Position in the hash chain
	HeadHash   string    `json:"head_hash"`   // Hash of the last event
	CreatedAt  time.Time `json:"created_at"`  // Creation timestamp (UTC)
}

// SignedCheckpoint wraps a checkpoint with a detached signature.
//
// This structure combines a checkpoint with its digital signature, creating
// a tamper-evident record that can be verified using the corresponding public key.
// The signature is base64-encoded and covers the canonicalized checkpoint data.
//
// Fields:
//   - Checkpoint: The checkpoint data that was signed
//   - Signature: Base64-encoded ECDSA signature of the canonicalized checkpoint
type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"` // The checkpoint data
	Signature  string     `json:"signature"`  // Base64-encoded ECDSA signature
}

// VerifySummary is appended to the run log to record verify runs.
//
// This structure captures the results and metadata of a verification run,
// providing a comprehensive audit trail of what was processed and any issues
// that were detected. It's used for logging and monitoring purposes.
//
// Fields:
//   - Phase: The processing phase (e.g., "verify")
//   - Mode: The verification mode (e.g., "compute", "check")
//   - InputFile: Path to the input file that was processed
//   - OutputFile: Path to the output file (if any)
//   - EventsProcessed: Total number of events processed
//   - TamperedEvents: Indices of events that failed verification (if any)
//   - CheckpointsVerified: Whether checkpoint verification was performed
//   - CheckpointPath: Path to checkpoint file (if used)
//   - Status: Overall status of the verification run
//   - StartTime: When the verification started (RFC3339 format)
//   - EndTime: When the verification completed (RFC3339 format)
type VerifySummary struct {
	Phase               string `json:"phase"`                     // Processing phase
	Mode                string `json:"mode"`                      // Verification mode
	InputFile           string `json:"input_file"`                // Input file path
	OutputFile          string `json:"output_file,omitempty"`     // Output file path (optional)
	EventsProcessed     int    `json:"events_processed"`          // Number of events processed
	TamperedEvents      []int  `json:"tampered_events,omitempty"` // Indices of tampered events
	CheckpointsVerified bool   `json:"checkpoints_verified"`      // Whether checkpoints were verified
	CheckpointPath      string `json:"checkpoint_path,omitempty"` // Checkpoint file path (optional)
	Status              string `json:"status"`                    // Overall status
	StartTime           string `json:"start_time"`                // Start timestamp (RFC3339)
	EndTime             string `json:"end_time"`                  // End timestamp (RFC3339)
}

package verify

import "time"

// ChainState stores rolling head and index for multi-file continuity.
// It allows subsequent runs to continue the hash chain seamlessly.
type ChainState struct {
	LastChainIndex int    `json:"last_chain_index"`
	LastHeadHash   string `json:"last_head_hash"`
}

// Checkpoint captures the chain head at a given chain index.
// This is the payload that gets signed and persisted.
type Checkpoint struct {
	ChainIndex int       `json:"chain_index"`
	HeadHash   string    `json:"head_hash"`
	CreatedAt  time.Time `json:"created_at"`
}

// SignedCheckpoint wraps a checkpoint with a detached signature.
type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Signature  string     `json:"signature"`
}

// VerifySummary is appended to the run log to record verify runs.
type VerifySummary struct {
	Phase               string `json:"phase"`
	Mode                string `json:"mode"`
	InputFile           string `json:"input_file"`
	OutputFile          string `json:"output_file,omitempty"`
	EventsProcessed     int    `json:"events_processed"`
	TamperedEvents      []int  `json:"tampered_events,omitempty"`
	CheckpointsVerified bool   `json:"checkpoints_verified"`
	CheckpointPath      string `json:"checkpoint_path,omitempty"`
	Status              string `json:"status"`
	StartTime           string `json:"start_time"`
	EndTime             string `json:"end_time"`
}

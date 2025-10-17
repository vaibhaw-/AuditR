package verify

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadState loads chain state from file; returns defaults if missing.
//
// This function loads the persistent state of a hash chain from a JSON file.
// The state contains the last processed chain index and the head hash, allowing
// the chain to be resumed from where it left off in previous runs.
//
// If the state file doesn't exist or is invalid, default values are returned:
// - LastChainIndex: 0 (start of chain)
// - LastHeadHash: 64-character zero string (initial hash)
//
// Args:
//   - path: Path to the state file (empty string means no state file)
//
// Returns:
//   - ChainState with loaded or default values
//   - Error if state file exists but cannot be read/parsed
func LoadState(path string) (*ChainState, error) {
	// If no path provided, return default state
	if path == "" {
		return &ChainState{LastChainIndex: 0, LastHeadHash: zeroHash()}, nil
	}

	// Open state file
	f, err := os.Open(path)
	if err != nil {
		// If file doesn't exist, return default state (not an error)
		if os.IsNotExist(err) {
			return &ChainState{LastChainIndex: 0, LastHeadHash: zeroHash()}, nil
		}
		return nil, fmt.Errorf("open state: %w", err)
	}
	defer f.Close()

	// Parse JSON state
	var st ChainState
	if err := json.NewDecoder(f).Decode(&st); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}

	// Ensure head hash is valid (fallback to zero hash if empty)
	if st.LastHeadHash == "" {
		st.LastHeadHash = zeroHash()
	}

	return &st, nil
}

// SaveState writes state atomically using a temp file + rename.
//
// This function saves the chain state to a JSON file using an atomic write pattern
// to prevent corruption. The process:
// 1. Write to a temporary file (path.tmp)
// 2. Close the temporary file
// 3. Atomically rename the temporary file to the final path
//
// This ensures that if the process is interrupted, either the old state is preserved
// or the new state is completely written - never a partial/corrupted state.
//
// Args:
//   - path: Path where to save the state file (empty string means no save)
//   - state: ChainState to persist
//
// Returns:
//   - Error if state cannot be saved
func SaveState(path string, state *ChainState) error {
	// If no path provided, skip saving (not an error)
	if path == "" {
		return nil
	}

	// Create temporary file for atomic write
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}

	// Configure JSON encoder for clean output
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false) // Don't escape HTML characters for cleaner JSON

	// Write state to temporary file
	if err := enc.Encode(state); err != nil {
		f.Close()
		os.Remove(tmp) // Clean up temp file on error
		return fmt.Errorf("encode state: %w", err)
	}

	// Close temporary file
	if err := f.Close(); err != nil {
		os.Remove(tmp) // Clean up temp file on error
		return fmt.Errorf("close temp state: %w", err)
	}

	// Atomically rename temp file to final path
	// This is atomic on most filesystems and prevents corruption
	return os.Rename(tmp, path)
}

// zeroHash returns a 64-character string of zeros used as the initial hash
//
// This represents the "genesis" hash for a new hash chain. Since SHA-256 produces
// 32 bytes (256 bits), the hex-encoded representation is 64 characters long.
// Using all zeros as the initial hash ensures deterministic chain computation.
//
// Returns:
//   - 64-character string of '0' characters
func zeroHash() string {
	// 64 zeros to match hex-encoded SHA-256 length
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

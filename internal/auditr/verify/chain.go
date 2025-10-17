package verify

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// ComputeChain reads NDJSON events, computes hash chain and writes augmented events.
//
// This function implements a cryptographic hash chain where each event's hash depends
// on the previous event's hash, creating an immutable audit trail. The chain ensures
// that any modification to a past event will be detected when verifying the chain.
//
// Hash Chain Algorithm:
// 1. Start with a zero hash (or previous chain head)
// 2. For each event:
//   - Canonicalize the event (remove hash fields, sort keys, normalize timestamps)
//   - Compute: hash = SHA256(previous_hash + "|" + canonicalized_event)
//   - Augment event with: hash_prev, hash, hash_chain_index
//   - Write augmented event to output
//
// Args:
//   - input: NDJSON stream of events to process
//   - output: Where to write the augmented events
//   - state: Previous chain state (nil for new chain)
//
// Returns:
//   - Updated chain state with final index and head hash
//   - Number of events processed
//   - Error if any step fails
func ComputeChain(input io.Reader, output io.Writer, state *ChainState) (*ChainState, int, error) {
	log := logger.L()

	// Initialize state if not provided (start of new chain)
	if state == nil {
		s := &ChainState{LastChainIndex: 0, LastHeadHash: zeroHash()}
		state = s
	}

	start := time.Now()
	log.Debugw("verify.compute: start", "start_index", state.LastChainIndex)

	// Set up buffered I/O for efficient processing
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	// Initialize chain state from previous run
	head := state.LastHeadHash    // Previous event's hash (or zero hash for new chain)
	index := state.LastChainIndex // Last processed event index
	processed := 0                // Counter for events processed in this run

	// Process each event in the input stream
	for scanner.Scan() {
		line := scanner.Bytes()
		var evt map[string]interface{}

		// Parse JSON event
		if err := json.Unmarshal(line, &evt); err != nil {
			return nil, processed, fmt.Errorf("decode event: %w", err)
		}

		// Canonicalize event for consistent hashing
		// This removes hash fields, sorts keys, and normalizes timestamps
		canon, err := Canonicalize(evt)
		if err != nil {
			return nil, processed, fmt.Errorf("canonicalize: %w", err)
		}

		// Compute hash chain: SHA256(previous_hash + "|" + canonicalized_event)
		// The "|" separator prevents hash collision attacks
		h := sha256.Sum256([]byte(head + "|" + canon))
		newHead := hex.EncodeToString(h[:])

		// Augment event with hash chain metadata
		evt["hash_prev"] = head         // Previous event's hash
		evt["hash"] = newHead           // This event's hash
		index++                         // Increment chain index
		evt["hash_chain_index"] = index // Position in the chain

		// Serialize and write augmented event
		out, err := json.Marshal(evt)
		if err != nil {
			return nil, processed, fmt.Errorf("encode event: %w", err)
		}
		if _, err := writer.Write(append(out, '\n')); err != nil {
			return nil, processed, fmt.Errorf("write event: %w", err)
		}

		// Update chain state for next iteration
		head = newHead
		processed++
	}
	// Check for scanner errors (e.g., truncated input)
	if err := scanner.Err(); err != nil {
		return nil, processed, fmt.Errorf("scan input: %w", err)
	}

	log.Infow("verify.compute: done", "events", processed, "end_index", index, "duration", time.Since(start))

	// Return updated state for potential continuation
	return &ChainState{LastChainIndex: index, LastHeadHash: head}, processed, nil
}

// VerifyChain validates a hashed NDJSON file, returning tampered indices and final head.
//
// This function verifies the integrity of a hash chain by recomputing each event's hash
// and comparing it with the stored hash. Any mismatch indicates tampering.
//
// Verification Process:
// 1. For each event, extract the stored hash_prev, hash, and hash_chain_index
// 2. Canonicalize the event (same process as during chain creation)
// 3. Recompute hash using: SHA256(hash_prev + "|" + canonicalized_event)
// 4. Compare computed hash with stored hash
// 5. Check that hash_prev matches the previous event's hash
// 6. Record any mismatches as tampered events
//
// Args:
//   - input: NDJSON stream of events with hash chain metadata
//
// Returns:
//   - Slice of tampered event indices (empty if no tampering detected)
//   - Final head hash of the chain
//   - Total number of events processed
//   - Error if verification fails
func VerifyChain(input io.Reader) ([]int, string, int, error) {
	log := logger.L()
	start := time.Now()
	log.Debugw("verify.check: start")
	scanner := bufio.NewScanner(input)

	// Initialize verification state
	tampered := make([]int, 0) // Track indices of tampered events
	head := zeroHash()         // Start with zero hash (first event should have this as hash_prev)
	processed := 0             // Count of events processed

	// Verify each event in the chain
	for scanner.Scan() {
		line := scanner.Bytes()
		var evt map[string]interface{}

		// Parse JSON event
		if err := json.Unmarshal(line, &evt); err != nil {
			return tampered, head, processed, fmt.Errorf("decode event: %w", err)
		}

		// Extract hash chain metadata from the event
		prev, _ := evt["hash_prev"].(string)             // Previous event's hash
		got, _ := evt["hash"].(string)                   // This event's stored hash
		idxFloat, _ := evt["hash_chain_index"].(float64) // Chain index (JSON numbers are float64)
		idx := int(idxFloat)                             // Convert to int

		// Recompute hash using the same algorithm as during chain creation
		canon, err := Canonicalize(evt)
		if err != nil {
			return tampered, head, processed, fmt.Errorf("canonicalize: %w", err)
		}
		calc := sha256.Sum256([]byte(prev + "|" + canon))
		want := hex.EncodeToString(calc[:])

		// Check for tampering: hash mismatch or broken chain
		if prev != head || want != got {
			tampered = append(tampered, idx)
		}

		// Update head for next iteration
		head = got
		processed++
	}
	// Check for scanner errors (e.g., truncated input)
	if err := scanner.Err(); err != nil {
		return tampered, head, processed, fmt.Errorf("scan input: %w", err)
	}

	log.Infow("verify.check: done", "events", processed, "tampered", len(tampered), "duration", time.Since(start))
	return tampered, head, processed, nil
}

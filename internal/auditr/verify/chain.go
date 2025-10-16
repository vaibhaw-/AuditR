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
// Returns updated state and number of processed events.
func ComputeChain(input io.Reader, output io.Writer, state *ChainState) (*ChainState, int, error) {
	log := logger.L()
	if state == nil {
		s := &ChainState{LastChainIndex: 0, LastHeadHash: zeroHash()}
		state = s
	}
	start := time.Now()
	log.Debugw("verify.compute: start", "start_index", state.LastChainIndex)
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	head := state.LastHeadHash
	index := state.LastChainIndex
	processed := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		var evt map[string]interface{}
		if err := json.Unmarshal(line, &evt); err != nil {
			return nil, processed, fmt.Errorf("decode event: %w", err)
		}
		canon, err := Canonicalize(evt)
		if err != nil {
			return nil, processed, fmt.Errorf("canonicalize: %w", err)
		}
		h := sha256.Sum256([]byte(head + "|" + canon))
		newHead := hex.EncodeToString(h[:])

		// augment event
		evt["hash_prev"] = head
		evt["hash"] = newHead
		index++
		evt["hash_chain_index"] = index

		out, err := json.Marshal(evt)
		if err != nil {
			return nil, processed, fmt.Errorf("encode event: %w", err)
		}
		if _, err := writer.Write(append(out, '\n')); err != nil {
			return nil, processed, fmt.Errorf("write event: %w", err)
		}

		head = newHead
		processed++
	}
	if err := scanner.Err(); err != nil {
		return nil, processed, fmt.Errorf("scan input: %w", err)
	}

	log.Infow("verify.compute: done", "events", processed, "end_index", index, "duration", time.Since(start))
	return &ChainState{LastChainIndex: index, LastHeadHash: head}, processed, nil
}

// VerifyChain validates a hashed NDJSON file, returning tampered indices and final head.
func VerifyChain(input io.Reader) ([]int, string, int, error) {
	log := logger.L()
	start := time.Now()
	log.Debugw("verify.check: start")
	scanner := bufio.NewScanner(input)
	tampered := make([]int, 0)
	head := zeroHash()
	processed := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		var evt map[string]interface{}
		if err := json.Unmarshal(line, &evt); err != nil {
			return tampered, head, processed, fmt.Errorf("decode event: %w", err)
		}

		// Extract expected
		prev, _ := evt["hash_prev"].(string)
		got, _ := evt["hash"].(string)
		idxFloat, _ := evt["hash_chain_index"].(float64)
		idx := int(idxFloat)

		// Recompute
		canon, err := Canonicalize(evt)
		if err != nil {
			return tampered, head, processed, fmt.Errorf("canonicalize: %w", err)
		}
		calc := sha256.Sum256([]byte(prev + "|" + canon))
		want := hex.EncodeToString(calc[:])

		if prev != head || want != got {
			tampered = append(tampered, idx)
		}

		head = got
		processed++
	}
	if err := scanner.Err(); err != nil {
		return tampered, head, processed, fmt.Errorf("scan input: %w", err)
	}
	log.Infow("verify.check: done", "events", processed, "tampered", len(tampered), "duration", time.Since(start))
	return tampered, head, processed, nil
}

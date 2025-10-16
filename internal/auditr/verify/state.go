package verify

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadState loads chain state from file; returns defaults if missing.
// Defaults: index=0, head=64 zero hex string.
func LoadState(path string) (*ChainState, error) {
	if path == "" {
		return &ChainState{LastChainIndex: 0, LastHeadHash: zeroHash()}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ChainState{LastChainIndex: 0, LastHeadHash: zeroHash()}, nil
		}
		return nil, fmt.Errorf("open state: %w", err)
	}
	defer f.Close()
	var st ChainState
	if err := json.NewDecoder(f).Decode(&st); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if st.LastHeadHash == "" {
		st.LastHeadHash = zeroHash()
	}
	return &st, nil
}

// SaveState writes state atomically using a temp file + rename.
func SaveState(path string, state *ChainState) error {
	if path == "" {
		return nil
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(state); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("encode state: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp state: %w", err)
	}
	return os.Rename(tmp, path)
}

func zeroHash() string {
	// 64 zeros to match hex-encoded SHA-256 length
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

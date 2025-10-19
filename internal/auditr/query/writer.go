package query

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteEventNDJSON writes an event as NDJSON (newline-delimited JSON) to the writer.
// This function serializes an event to JSON and writes it as a single line (NDJSON format).
// Each event is written on its own line, making it suitable for streaming and pipeline operations.
//
// The function preserves all fields from the original event without any projection or filtering.
// This ensures that the output contains the complete audit event data.
//
// Error handling:
// - JSON marshaling errors are returned as wrapped errors
// - I/O errors are returned as wrapped errors
func WriteEventNDJSON(w io.Writer, event Event) error {
	// Marshal event to JSON (preserves all fields)
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event to JSON: %w", err)
	}

	// Write JSON line with newline (NDJSON format)
	_, err = fmt.Fprintln(w, string(data))
	if err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

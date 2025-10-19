package query

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ReadEvents reads NDJSON events from files or stdin and sends them on a channel.
// This function implements streaming processing for large audit log files.
//
// Behavior:
// - If no files specified, reads from stdin
// - If multiple files specified, processes them sequentially
// - Each line is parsed as JSON and sent on the channel
// - Malformed JSON lines are sent as errors but don't stop processing
// - Empty lines are skipped
// - Uses buffered channel (100 events) for better performance
//
// The returned channel will be closed when all files are processed or an error occurs.
func ReadEvents(files []string) <-chan EventResult {
	// Buffered channel for better performance - allows producer/consumer to work independently
	ch := make(chan EventResult, 100)

	go func() {
		defer close(ch)

		// If no files specified, read from stdin (supports pipeline operations)
		if len(files) == 0 {
			readFromReader(os.Stdin, "stdin", ch)
			return
		}

		// Read from each file sequentially
		// This approach is simple and handles file errors gracefully
		for _, file := range files {
			f, err := os.Open(file)
			if err != nil {
				// Send error on channel but continue with other files
				ch <- EventResult{
					Event: nil,
					Err:   fmt.Errorf("failed to open file %s: %w", file, err),
				}
				continue
			}

			readFromReader(f, file, ch)
			f.Close()
		}
	}()

	return ch
}

// readFromReader reads NDJSON lines from a reader and sends events on the channel.
// This is the core parsing logic that handles individual files or stdin.
//
// Processing:
// - Uses bufio.Scanner for efficient line-by-line reading
// - Skips empty lines (common in audit logs)
// - Parses each line as JSON into map[string]any
// - Sends both successful events and parse errors on the channel
// - Tracks line numbers for better error reporting
//
// Error handling:
// - JSON parse errors are sent as EventResult with Err set
// - Scanner errors (I/O issues) are sent as EventResult with Err set
// - Processing continues even after errors (resilient design)
func readFromReader(r io.Reader, source string, ch chan<- EventResult) {
	scanner := bufio.NewScanner(r)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Skip empty lines - common in audit logs due to formatting
		if line == "" {
			continue
		}

		// Parse JSON line into Event (map[string]any)
		// This preserves all fields from the original NDJSON
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// Send parse error on channel but continue processing
			// This allows the main loop to count errors and continue
			ch <- EventResult{
				Event: nil,
				Err:   fmt.Errorf("JSON parse error in %s line %d: %w", source, lineNumber, err),
			}
			continue
		}

		// Send successfully parsed event
		ch <- EventResult{
			Event: event,
			Err:   nil,
		}
	}

	// Check for scanner errors (I/O issues, file truncated, etc.)
	if err := scanner.Err(); err != nil {
		ch <- EventResult{
			Event: nil,
			Err:   fmt.Errorf("scanner error in %s: %w", source, err),
		}
	}
}

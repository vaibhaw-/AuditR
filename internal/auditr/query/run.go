package query

import (
	"fmt"
	"io"
	"os"
)

// RunQuery is the main orchestration function that processes events according to the query options.
// This function coordinates all components of the query system:
// - Building filters from CLI options
// - Opening input/output streams
// - Processing events through filters
// - Collecting statistics
// - Writing results and summaries
//
// The function implements streaming processing for efficient handling of large audit logs.
// It processes events one at a time and applies all filters using AND logic.
//
// Error handling:
// - Malformed JSON events are counted but don't stop processing
// - I/O errors are returned as wrapped errors
// - Filter errors are logged but don't stop processing
func RunQuery(opts QueryOptions) error {
	// Build filters from CLI options
	// This creates the filter chain based on user-specified criteria
	filters := buildFilters(opts)

	// Open output writer (stdout or file)
	output, err := openOutput(opts.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to open output: %w", err)
	}
	// Ensure output is closed if it's a file
	if closer, ok := output.(io.Closer); ok {
		defer closer.Close()
	}

	// Initialize statistics tracking
	stats := NewStats()

	// Process events from input stream
	// This is the main processing loop that handles each event
	for result := range ReadEvents(opts.InputFiles) {
		// Handle parsing errors gracefully
		if result.Err != nil {
			stats.IncrementError() // Count error events
			continue               // Skip to next event
		}

		stats.IncrementInput() // Count every valid event processed

		// Apply all filters using AND logic
		// Event must match ALL filters to be included
		if matchAll(result.Event, filters) {
			stats.IncrementMatched(result.Event) // Update statistics

			// Only write events to output if not in summary-only mode
			// When --summary is specified without --output, only print summary to stderr
			if !opts.Summary || opts.OutputFile != "" {
				// Write matching event to output
				if err := WriteEventNDJSON(output, result.Event); err != nil {
					return fmt.Errorf("failed to write event: %w", err)
				}
			}

			// Check if we've reached the limit
			if opts.Limit > 0 && stats.MatchedEvents >= opts.Limit {
				break // Stop processing when limit is reached
			}
		}
	}

	// Print summary statistics if requested
	if opts.Summary {
		stats.PrintSummary(os.Stderr) // Summary goes to stderr, events to stdout
	}

	return nil
}

// buildFilters creates a list of filters based on the query options.
// This function translates CLI options into a chain of filter functions.
// Only non-empty options are converted to filters, ensuring efficient processing.
//
// Filter order:
// 1. Sensitivity categories (PII, PHI, Financial)
// 2. User and IP filters
// 3. Query type filters
// 4. Bulk operation filter
// 5. Sensitive field filters
// 6. Time-based filters
// 7. Error exclusion filter
//
// All filters are combined using AND logic in the main processing loop.
func buildFilters(opts QueryOptions) []EventFilter {
	var filters []EventFilter

	// Sensitivity filter - match by sensitivity categories
	if len(opts.Sensitivity) > 0 {
		filters = append(filters, FilterBySensitivity(opts.Sensitivity))
	}

	// User filter - match by database user
	if opts.User != "" {
		filters = append(filters, FilterByUser(opts.User))
	}

	// IP filter - match by client IP address
	if opts.IP != "" {
		filters = append(filters, FilterByIP(opts.IP))
	}

	// Query type filter - match by query types (SELECT, INSERT, etc.)
	if len(opts.Types) > 0 {
		filters = append(filters, FilterByType(opts.Types))
	}

	// Bulk filter - match bulk operations only
	if opts.Bulk {
		filters = append(filters, FilterByBulk())
	}

	// Bulk type filter - match specific bulk operation types
	if opts.BulkType != "" {
		filters = append(filters, FilterByBulkType(opts.BulkType))
	}

	// Sensitive fields filter - match by field names in sensitivity entries
	if len(opts.FilterFields) > 0 {
		filters = append(filters, FilterBySensitiveFields(opts.FilterFields))
	}

	// Time filter - match by time range (--since or --last)
	if !opts.Since.IsZero() || opts.LastDuration > 0 {
		filters = append(filters, FilterByTime(opts.Since, opts.LastDuration))
	}

	// Exclude errors filter - filter out ERROR events
	if opts.ExcludeErrors {
		filters = append(filters, FilterExcludeErrors())
	}

	return filters
}

// openOutput opens the output file or returns stdout.
// This function handles the --output flag by either creating a file or using stdout.
//
// Behavior:
// - If outputFile is empty, returns os.Stdout (default behavior)
// - If outputFile is specified, creates/truncates the file
// - Returns an error if file creation fails
//
// The returned writer should be closed by the caller if it's a file.
func openOutput(outputFile string) (io.Writer, error) {
	if outputFile == "" {
		return os.Stdout, nil // Default to stdout
	}

	// Create/truncate the output file
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file %s: %w", outputFile, err)
	}

	return file, nil
}

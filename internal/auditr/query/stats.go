package query

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// Stats tracks comprehensive statistics about processed events.
// This struct is used to generate the summary output and provides insights into
// the audit log data being processed.
//
// Fields:
// - InputEvents: Total number of events processed (including errors)
// - MatchedEvents: Number of events that passed all filters
// - ErrorEvents: Number of events that failed to parse or had I/O errors
// - BySensitivity: Breakdown by sensitivity categories (PII, PHI, Financial)
// - ByQueryType: Breakdown by query types (SELECT, INSERT, UPDATE, DELETE, etc.)
// - ByRiskLevel: Breakdown by risk levels (low, medium, high, critical)
// - BulkCount: Number of bulk operations found
// - FirstTimestamp/LastTimestamp: Time range of processed events
type Stats struct {
	InputEvents    int            // Total events processed (including errors)
	MatchedEvents  int            // Events that passed all filters
	ErrorEvents    int            // Events that failed to parse or had I/O errors
	BySensitivity  map[string]int // Count by sensitivity category (PII, PHI, Financial)
	ByQueryType    map[string]int // Count by query type (SELECT, INSERT, UPDATE, etc.)
	ByRiskLevel    map[string]int // Count by risk level (low, medium, high, critical)
	BulkCount      int            // Number of bulk operations
	FirstTimestamp *time.Time     // Earliest event timestamp
	LastTimestamp  *time.Time     // Latest event timestamp
}

// NewStats creates a new Stats instance with initialized maps.
// This constructor ensures all map fields are properly initialized to avoid nil pointer panics.
func NewStats() *Stats {
	return &Stats{
		BySensitivity: make(map[string]int),
		ByQueryType:   make(map[string]int),
		ByRiskLevel:   make(map[string]int),
	}
}

// IncrementInput increments the input events counter.
// This should be called for every event processed, regardless of whether it matches filters.
func (s *Stats) IncrementInput() {
	s.InputEvents++
}

// IncrementError increments the error events counter.
// This should be called for events that failed to parse or had I/O errors.
func (s *Stats) IncrementError() {
	s.ErrorEvents++
}

// IncrementMatched increments the matched events counter and updates all relevant statistics.
// This is the main function for tracking statistics about events that passed all filters.
// It updates all breakdown counters and tracks the time range of processed events.
//
// Statistics updated:
// - MatchedEvents: Total count of matching events
// - BySensitivity: Count by sensitivity categories (PII, PHI, Financial)
// - ByQueryType: Count by query types (SELECT, INSERT, UPDATE, etc.)
// - ByRiskLevel: Count by risk levels (low, medium, high, critical)
// - BulkCount: Count of bulk operations
// - FirstTimestamp/LastTimestamp: Time range of all matched events
func (s *Stats) IncrementMatched(e Event) {
	s.MatchedEvents++

	// Update sensitivity breakdown - count each category found in the event
	if sensitivity, ok := GetStringSlice(e, "sensitivity"); ok {
		for _, entry := range sensitivity {
			category, _ := ParseSensitivityEntry(entry) // Extract category part (before colon)
			if category != "" {
				s.BySensitivity[category]++ // Increment count for this sensitivity category
			}
		}
	}

	// Update query type breakdown - count the query type
	if queryType, ok := GetString(e, "query_type"); ok {
		s.ByQueryType[queryType]++ // Increment count for this query type
	}

	// Update risk level breakdown - count the risk level
	if riskLevel, ok := GetString(e, "risk_level"); ok {
		s.ByRiskLevel[riskLevel]++ // Increment count for this risk level
	}

	// Update bulk count - count bulk operations
	if bulk, ok := GetBool(e, "bulk"); ok && bulk {
		s.BulkCount++ // Increment bulk operations counter
	}

	// Update time range - track earliest and latest timestamps
	if timestamp, err := ParseTimestamp(e["timestamp"]); err == nil {
		// Update first timestamp (earliest)
		if s.FirstTimestamp == nil || timestamp.Before(*s.FirstTimestamp) {
			s.FirstTimestamp = &timestamp
		}
		// Update last timestamp (latest)
		if s.LastTimestamp == nil || timestamp.After(*s.LastTimestamp) {
			s.LastTimestamp = &timestamp
		}
	}
}

// PrintSummary prints a formatted summary to the writer.
// This generates the human-readable summary output that appears when --summary flag is used.
// The output includes comprehensive statistics about processed events and their breakdowns.
//
// Output format:
// - Total events processed (including errors)
// - Time range of matched events (if available)
// - Number of matched events
// - Breakdown by sensitivity categories (PII, PHI, Financial)
// - Breakdown by query types (SELECT, INSERT, UPDATE, etc.)
// - Breakdown by risk levels (low, medium, high, critical)
// - Count of bulk operations
//
// The breakdowns are sorted by count (descending) then by name (ascending) for readability.
func (s *Stats) PrintSummary(w io.Writer) {
	fmt.Fprintf(w, "Summary:\n")
	fmt.Fprintf(w, "  Total events processed: %d\n", s.InputEvents)

	// Time range - show the span of matched events
	if s.FirstTimestamp != nil && s.LastTimestamp != nil {
		fmt.Fprintf(w, "  Time range: %s to %s\n",
			s.FirstTimestamp.Format(time.RFC3339),
			s.LastTimestamp.Format(time.RFC3339))
	}

	fmt.Fprintf(w, "  Matched: %d\n", s.MatchedEvents)
	fmt.Fprintf(w, "\n")

	// Sensitivity breakdown - show counts by sensitivity category
	if len(s.BySensitivity) > 0 {
		fmt.Fprintf(w, "  By sensitivity:\n")
		s.printSortedMap(w, s.BySensitivity, "    ")
		fmt.Fprintf(w, "\n")
	}

	// Query type breakdown - show counts by query type
	if len(s.ByQueryType) > 0 {
		fmt.Fprintf(w, "  By query type:\n")
		s.printSortedMap(w, s.ByQueryType, "    ")
		fmt.Fprintf(w, "\n")
	}

	// Risk level breakdown - show counts by risk level
	if len(s.ByRiskLevel) > 0 {
		fmt.Fprintf(w, "  By risk level:\n")
		s.printSortedMap(w, s.ByRiskLevel, "    ")
		fmt.Fprintf(w, "\n")
	}

	// Bulk operations count - show count of bulk operations
	if s.BulkCount > 0 {
		fmt.Fprintf(w, "  Bulk operations: %d\n", s.BulkCount)
	}
}

// printSortedMap prints a map sorted by value (descending) then by key (ascending).
// This helper function is used to display breakdown statistics in a consistent, readable format.
// Items with the same count are sorted alphabetically by key for predictable output.
//
// Examples:
// - "PII: 15, PHI: 8, Financial: 3" (sorted by count descending)
// - "SELECT: 20, INSERT: 20, UPDATE: 5" (same count sorted alphabetically)
func (s *Stats) printSortedMap(w io.Writer, m map[string]int, indent string) {
	// Create slice of key-value pairs for sorting
	type kv struct {
		key   string
		value int
	}

	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}

	// Sort by value (descending) then by key (ascending)
	// This ensures consistent, readable output
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].value == pairs[j].value {
			return pairs[i].key < pairs[j].key // Same count: sort alphabetically
		}
		return pairs[i].value > pairs[j].value // Different count: sort by count descending
	})

	// Print sorted pairs with proper indentation
	for _, pair := range pairs {
		fmt.Fprintf(w, "%s%s: %d\n", indent, pair.key, pair.value)
	}
}

// GetSummaryMap returns the statistics as a map for programmatic access
func (s *Stats) GetSummaryMap() map[string]interface{} {
	summary := map[string]interface{}{
		"total_events_processed": s.InputEvents,
		"matched_events":         s.MatchedEvents,
		"error_events":           s.ErrorEvents,
		"by_sensitivity":         s.BySensitivity,
		"by_query_type":          s.ByQueryType,
		"by_risk_level":          s.ByRiskLevel,
		"bulk_operations":        s.BulkCount,
	}

	if s.FirstTimestamp != nil && s.LastTimestamp != nil {
		summary["time_range"] = map[string]string{
			"start": s.FirstTimestamp.Format(time.RFC3339),
			"end":   s.LastTimestamp.Format(time.RFC3339),
		}
	}

	return summary
}

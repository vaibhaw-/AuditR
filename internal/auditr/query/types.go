package query

import "time"

// Event represents a parsed audit event as a map of string keys to any values.
// This is the canonical representation of an audit event after JSON unmarshaling.
// All fields from the original NDJSON are preserved, including:
// - Core fields: timestamp, db_user, query_type, risk_level
// - Sensitivity data: sensitivity array with "Category:field" entries
// - Bulk operation flags: bulk, bulk_type, full_table_read
// - Hash chain data: hash, hash_prev, hash_chain_index (from verify phase)
// - Database-specific fields: client_ip, connection_id, db_system, etc.
type Event = map[string]any

// QueryOptions contains all CLI flags and options for the query command.
// This struct is populated from Cobra flags and passed to the main RunQuery function.
// All filtering, output, and processing options are centralized here.
type QueryOptions struct {
	// Input/Output configuration
	InputFiles []string // Input NDJSON file(s), empty means stdin
	OutputFile string   // Output file path, empty means stdout

	// Sensitivity-based filtering
	Sensitivity  []string // Filter by sensitivity categories (PII, PHI, Financial)
	FilterFields []string // Filter by field names in sensitivity entries (email, ssn, etc.)

	// User and connection filtering
	User string // Filter by database user (db_user field)
	IP   string // Filter by client IP address (client_ip field)

	// Query type and operation filtering
	Types    []string // Filter by query types (SELECT, INSERT, UPDATE, DELETE, etc.)
	Bulk     bool     // Show only bulk operations (bulk == true)
	BulkType string   // Filter by specific bulk operation type (export, import, backup, etc.)

	// Time-based filtering
	Since        time.Time     // Include events on or after this time (ISO 8601 UTC)
	LastDuration time.Duration // Include events from the last N days/hours

	// Error handling and output options
	ExcludeErrors bool // Exclude events with query_type == "ERROR"
	Summary       bool // Print summary counts instead of full events
	Limit         int  // Limit number of output events (0 = no limit)
}

// EventFilter is a function that determines if an event matches certain criteria.
// Filters are composable and can be combined using AND logic.
// Each filter should handle missing fields gracefully (treat as non-match).
type EventFilter func(Event) bool

// EventResult represents the result of reading an event from input.
// This is used for channel communication between the reader and main processing loop.
// Errors are sent on the channel rather than stopping processing entirely.
type EventResult struct {
	Event Event // The parsed event (nil if parsing failed)
	Err   error // Error encountered during reading/parsing (nil if successful)
}

package query

import (
	"time"
)

// FilterBySensitivity creates a filter that matches events with specific sensitivity categories.
// This filter looks for sensitivity entries that start with the requested categories.
//
// Examples:
// - FilterBySensitivity(["PII"]) matches events with sensitivity ["PII:email", "PHI:diagnosis"]
// - FilterBySensitivity(["PHI", "Financial"]) matches events with any PHI or Financial entries
//
// The filter is case-insensitive and treats missing sensitivity field as non-match.
func FilterBySensitivity(categories []string) EventFilter {
	return func(e Event) bool {
		// Extract sensitivity array from event
		sensitivity, ok := GetStringSlice(e, "sensitivity")
		if !ok || len(sensitivity) == 0 {
			return false // No sensitivity data = no match
		}

		// Check each sensitivity entry for matching categories
		for _, entry := range sensitivity {
			category, _ := ParseSensitivityEntry(entry) // Extract category part (before colon)
			if matchesAny(category, categories) {
				return true // Found at least one matching category
			}
		}
		return false // No matching categories found
	}
}

// FilterByUser creates a filter that matches events by database user.
// This filter looks for the 'db_user' field in events and performs case-insensitive matching.
//
// Examples:
// - FilterByUser("appuser1") matches events where db_user = "appuser1" or "APPUSER1"
// - FilterByUser("root") matches events where db_user = "root" or "ROOT"
//
// The filter treats missing db_user field as non-match.
func FilterByUser(user string) EventFilter {
	return func(e Event) bool {
		dbUser, ok := GetString(e, "db_user")
		if !ok {
			return false // No db_user field = no match
		}
		return stringsEqualFold(dbUser, user) // Case-insensitive comparison
	}
}

// FilterByIP creates a filter that matches events by client IP address.
// This filter looks for the 'client_ip' field in events and performs case-insensitive matching.
//
// Examples:
// - FilterByIP("127.0.0.1") matches events where client_ip = "127.0.0.1"
// - FilterByIP("10.0.0.3") matches events where client_ip = "10.0.0.3"
//
// The filter treats missing client_ip field as non-match.
// Note: Not all events have client_ip (depends on database system and configuration).
func FilterByIP(ip string) EventFilter {
	return func(e Event) bool {
		clientIP, ok := GetString(e, "client_ip")
		if !ok {
			return false // No client_ip field = no match
		}
		return stringsEqualFold(clientIP, ip) // Case-insensitive comparison
	}
}

// FilterByType creates a filter that matches events by query type.
// This filter looks for the 'query_type' field and matches against multiple types.
//
// Examples:
// - FilterByType(["SELECT"]) matches only SELECT queries
// - FilterByType(["INSERT", "UPDATE"]) matches INSERT or UPDATE queries
// - FilterByType(["SELECT", "INSERT", "UPDATE", "DELETE"]) matches all DML operations
//
// The filter is case-insensitive and treats missing query_type field as non-match.
func FilterByType(types []string) EventFilter {
	return func(e Event) bool {
		queryType, ok := GetString(e, "query_type")
		if !ok {
			return false // No query_type field = no match
		}
		return matchesAny(queryType, types) // Check if query_type matches any of the requested types
	}
}

// FilterByBulk creates a filter that matches bulk operations.
// This filter looks for the 'bulk' field and matches events where bulk == true.
//
// Examples:
// - FilterByBulk() matches events where bulk = true
// - Used to find large data operations like exports, bulk inserts, etc.
//
// The filter treats missing bulk field as non-match (assumes non-bulk operation).
func FilterByBulk() EventFilter {
	return func(e Event) bool {
		bulk, ok := GetBool(e, "bulk")
		return ok && bulk // Must have bulk field AND it must be true
	}
}

// FilterByBulkType creates a filter that matches events with specific bulk operation types.
// This filter looks for the 'bulk_type' field and matches events with the specified type.
//
// Examples:
// - FilterByBulkType("export") matches events where bulk_type = "export"
// - FilterByBulkType("import") matches events where bulk_type = "import"
// - FilterByBulkType("backup") matches events where bulk_type = "backup"
//
// The filter is case-insensitive and treats missing bulk_type field as non-match.
func FilterByBulkType(bulkType string) EventFilter {
	return func(e Event) bool {
		eventBulkType, ok := GetString(e, "bulk_type")
		if !ok {
			return false // No bulk_type field = no match
		}
		return stringsEqualFold(eventBulkType, bulkType) // Case-insensitive comparison
	}
}

// FilterBySensitiveFields creates a filter that matches events containing specific field names in sensitivity entries.
// This filter looks for field names (after the colon) in sensitivity entries like "PII:email".
//
// Examples:
// - FilterBySensitiveFields(["email"]) matches events with sensitivity ["PII:email", "PHI:diagnosis"]
// - FilterBySensitiveFields(["ssn", "card_last4"]) matches events with SSN or card number fields
// - FilterBySensitiveFields(["diagnosis"]) matches events with medical diagnosis fields
//
// The filter is case-insensitive and treats missing sensitivity field as non-match.
func FilterBySensitiveFields(fields []string) EventFilter {
	return func(e Event) bool {
		sensitivity, ok := GetStringSlice(e, "sensitivity")
		if !ok || len(sensitivity) == 0 {
			return false // No sensitivity data = no match
		}

		// Check each sensitivity entry for matching field names
		for _, entry := range sensitivity {
			_, field := ParseSensitivityEntry(entry) // Extract field name part (after colon)
			if field != "" && matchesAny(field, fields) {
				return true // Found at least one matching field
			}
		}
		return false // No matching fields found
	}
}

// FilterByTime creates a filter that matches events within a time range.
// This filter supports both absolute time (--since) and relative time (--last) filtering.
//
// Examples:
// - FilterByTime(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), 0) matches events from Oct 1, 2025 onwards
// - FilterByTime(time.Time{}, 24*time.Hour) matches events from the last 24 hours
// - FilterByTime(time.Time{}, 7*24*time.Hour) matches events from the last 7 days
//
// Priority: If both since and last are specified, last takes precedence.
// The filter treats missing or invalid timestamp as non-match.
func FilterByTime(since time.Time, last time.Duration) EventFilter {
	return func(e Event) bool {
		// Parse timestamp from event (handles multiple formats)
		timestamp, err := ParseTimestamp(e["timestamp"])
		if err != nil {
			return false // Invalid timestamp = no match
		}

		// If last duration is specified, calculate the cutoff time (takes precedence)
		if last > 0 {
			cutoff := time.Now().Add(-last)
			return !timestamp.Before(cutoff) // Event must be on or after cutoff
		}

		// If since time is specified, check if event is on or after that time
		if !since.IsZero() {
			return !timestamp.Before(since) // Event must be on or after since time
		}

		// No time filtering specified - match all events
		return true
	}
}

// FilterExcludeErrors creates a filter that excludes ERROR events.
// This filter is used with the --exclude-errors flag to filter out malformed or error events.
//
// Examples:
// - FilterExcludeErrors() excludes events where query_type = "ERROR"
// - Used to clean up audit logs by removing parsing errors, connection failures, etc.
//
// The filter treats missing query_type field as non-ERROR (includes the event).
func FilterExcludeErrors() EventFilter {
	return func(e Event) bool {
		queryType, ok := GetString(e, "query_type")
		if !ok {
			return true // No query_type field = include the event (assume non-ERROR)
		}
		return !stringsEqualFold(queryType, "ERROR") // Include if not ERROR
	}
}

// matchAll applies all filters to an event using AND logic.
// This is the core function that combines multiple filters.
// An event must match ALL filters to be included in the results.
//
// Examples:
// - matchAll(event, [FilterByUser("alice"), FilterByType(["SELECT"])]) matches events where user=alice AND type=SELECT
// - matchAll(event, [FilterBySensitivity(["PII"]), FilterByBulk()]) matches events that are both PII-related AND bulk operations
//
// If no filters are provided, all events match (returns true).
func matchAll(event Event, filters []EventFilter) bool {
	for _, filter := range filters {
		if !filter(event) {
			return false // Event failed this filter - exclude it
		}
	}
	return true // Event passed all filters - include it
}

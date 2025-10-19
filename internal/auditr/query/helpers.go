package query

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GetString safely extracts a string value from an event map.
// Returns (value, ok) where ok is false if the key doesn't exist, is nil, or is not a string.
// This is the primary way to safely access string fields in events.
func GetString(e Event, key string) (string, bool) {
	if v, ok := e[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s, true
		}
	}
	return "", false
}

// GetBool safely extracts a boolean value from an event map.
// Returns (value, ok) where ok is false if the key doesn't exist, is nil, or is not a boolean.
// Used for fields like 'bulk' and 'full_table_read'.
func GetBool(e Event, key string) (bool, bool) {
	if v, ok := e[key]; ok && v != nil {
		if b, ok := v.(bool); ok {
			return b, true
		}
	}
	return false, false
}

// GetStringSlice safely extracts a string slice from an event map.
// Handles both []string (direct) and []interface{} (from JSON unmarshaling) types.
// Returns (slice, ok) where ok is false if the key doesn't exist, is nil, or is not a slice.
// Used for fields like 'sensitivity' array.
func GetStringSlice(e Event, key string) ([]string, bool) {
	if v, ok := e[key]; ok && v != nil {
		// Handle []string directly (when event is constructed programmatically)
		if slice, ok := v.([]string); ok {
			return slice, true
		}
		// Handle []interface{} (from JSON unmarshaling)
		if slice, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result, true
		}
	}
	return nil, false
}

// ParseTimestamp parses various timestamp formats into time.Time.
// Handles multiple common timestamp formats found in audit logs:
// - RFC3339 (preferred): "2025-10-01T12:34:56Z"
// - ISO 8601 variants: "2025-10-01T12:34:56.000Z", "2025-10-01 12:34:56"
// - time.Time objects (already parsed)
// Returns an error if the timestamp cannot be parsed or is nil.
func ParseTimestamp(v any) (time.Time, error) {
	if v == nil {
		return time.Time{}, fmt.Errorf("timestamp is nil")
	}

	switch t := v.(type) {
	case string:
		// Try RFC3339 first (most common format in audit logs)
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed, nil
		}
		// Try other common formats found in database audit logs
		formats := []string{
			"2006-01-02T15:04:05Z",     // ISO 8601 without milliseconds
			"2006-01-02T15:04:05.000Z", // ISO 8601 with milliseconds
			"2006-01-02 15:04:05",      // Space-separated format
			"2006-01-02T15:04:05",      // ISO 8601 without timezone
		}
		for _, format := range formats {
			if parsed, err := time.Parse(format, t); err == nil {
				return parsed, nil
			}
		}
		return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", t)
	case time.Time:
		// Already parsed timestamp
		return t, nil
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type: %T", v)
	}
}

// ParseDuration parses duration strings supporting 'd' (days) and 'h' (hours) units.
// This is a custom parser that extends Go's standard duration parsing to support
// common audit log time ranges like "7d" (7 days) and "24h" (24 hours).
// Examples: "7d", "24h", "168h", "1h30m", "45m", "30s"
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Remove any whitespace
	s = strings.TrimSpace(s)

	// Check for days (d) suffix - custom extension
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days value: %s", daysStr)
		}
		if days < 0 {
			return 0, fmt.Errorf("days cannot be negative: %d", days)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Check for hours (h) suffix - custom extension
	if strings.HasSuffix(s, "h") {
		hoursStr := strings.TrimSuffix(s, "h")
		hours, err := strconv.Atoi(hoursStr)
		if err != nil {
			return 0, fmt.Errorf("invalid hours value: %s", hoursStr)
		}
		if hours < 0 {
			return 0, fmt.Errorf("hours cannot be negative: %d", hours)
		}
		return time.Duration(hours) * time.Hour, nil
	}

	// Fall back to Go's standard duration parsing (supports h, m, s, etc.)
	// This handles formats like "1h30m", "45m", "30s", etc.
	return time.ParseDuration(s)
}

// stringsEqualFold performs case-insensitive string comparison.
// Used throughout the query system to ensure consistent case-insensitive matching.
func stringsEqualFold(a, b string) bool {
	return strings.EqualFold(a, b)
}

// containsString performs case-insensitive substring search.
// Used for partial matching within larger text fields.
func containsString(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// matchesAny checks if any string in the slice matches the target (case-insensitive).
// This is the core function for multi-value filtering (e.g., multiple query types).
// Returns true if any candidate matches the target string.
func matchesAny(target string, candidates []string) bool {
	for _, candidate := range candidates {
		if stringsEqualFold(target, candidate) {
			return true
		}
	}
	return false
}

// ParseSensitivityEntry parses a sensitivity entry like "PII:email" into category and field.
// The sensitivity array contains entries in the format "Category:field" where:
// - Category is the sensitivity type (PII, PHI, Financial)
// - Field is the specific field name (email, ssn, diagnosis, card_last4)
// If no colon is present, the entire string is treated as a category.
func ParseSensitivityEntry(entry string) (category, field string) {
	parts := strings.SplitN(entry, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return entry, "" // If no colon, treat as category only
}

// isValidDurationString validates if a string is a valid duration format.
// Used for CLI validation before attempting to parse durations.
// Supports both custom formats (7d, 24h) and standard Go formats (1h30m, 45m).
func isValidDurationString(s string) bool {
	// Check for days format (e.g., "7d", "1d")
	if matched, _ := regexp.MatchString(`^\d+d$`, s); matched {
		return true
	}
	// Check for hours format (e.g., "24h", "1h")
	if matched, _ := regexp.MatchString(`^\d+h$`, s); matched {
		return true
	}
	// Check for standard Go duration format (e.g., "1h30m", "45m", "30s")
	if _, err := time.ParseDuration(s); err == nil {
		return true
	}
	return false
}

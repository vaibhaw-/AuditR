package verify

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"
)

// Canonicalize returns a deterministic JSON string for hashing.
//
// This function creates a canonical representation of an event that is consistent
// across different runs and environments. It's essential for hash chain integrity
// because the same event must always produce the same hash.
//
// Canonicalization Rules:
//  1. Remove hash-related fields: hash, hash_prev, hash_chain_index
//     (These are computed from the canonical form, so they shouldn't be included)
//  2. Sort keys alphabetically at all levels (recursively)
//  3. Normalize timestamps to UTC RFC3339 format when parseable
//  4. Produce compact JSON output (no extra whitespace)
//  5. Deep copy the input to avoid modifying the original event
//
// Args:
//   - event: Event map to canonicalize
//
// Returns:
//   - Canonical JSON string representation
//   - Error if canonicalization fails
func Canonicalize(event map[string]interface{}) (string, error) {
	// Step 1: Deep copy event and remove hash-related fields
	clean := deepCopyWithoutHashFields(event)

	// Step 2: Normalize timestamps to UTC RFC3339 format
	normalizeTimestamps(clean)

	// Step 3: Encode with sorted keys to produce canonical JSON
	var buf bytes.Buffer
	if err := encodeSorted(&buf, clean); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// deepCopyWithoutHashFields creates a deep copy of the input map while excluding hash fields
//
// This function recursively copies all values in the input map except for the
// hash-related fields that are computed during chain processing. This ensures
// the original event is not modified and hash fields don't interfere with
// canonicalization.
//
// Args:
//   - in: Input map to copy
//
// Returns:
//   - Deep copy of input map without hash fields
func deepCopyWithoutHashFields(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		// Skip hash-related fields that are computed during chain processing
		if k == "hash" || k == "hash_prev" || k == "hash_chain_index" {
			continue
		}
		// Recursively copy the value
		out[k] = deepCopyValue(v)
	}
	return out
}

// deepCopyValue recursively copies a value, handling maps, slices, and primitives
//
// This function performs a deep copy of any value type, recursively processing
// nested maps and slices to ensure complete isolation from the original data.
// Primitive types (strings, numbers, booleans, etc.) are copied by value.
//
// Args:
//   - v: Value to deep copy
//
// Returns:
//   - Deep copy of the input value
func deepCopyValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		// Recursively copy nested maps
		m := make(map[string]interface{}, len(t))
		for k, vv := range t {
			m[k] = deepCopyValue(vv)
		}
		return m
	case []interface{}:
		// Recursively copy nested slices
		arr := make([]interface{}, len(t))
		for i := range t {
			arr[i] = deepCopyValue(t[i])
		}
		return arr
	default:
		// Primitive types are copied by value
		return t
	}
}

// normalizeTimestamps recursively normalizes timestamp strings to UTC RFC3339 format
//
// This function traverses the data structure and attempts to parse any string
// values as RFC3339 timestamps. If successful, it normalizes them to UTC and
// reformats them in RFC3339 format for consistency.
//
// The normalization is "best-effort" - if a string doesn't parse as RFC3339,
// it's left unchanged. This ensures that only valid timestamps are normalized
// while preserving other string data.
//
// Args:
//   - v: Value to normalize (modified in place)
func normalizeTimestamps(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		// Process each key-value pair in the map
		for k, vv := range t {
			// Try to parse string values as RFC3339 timestamps
			if s, ok := vv.(string); ok {
				if ts, err := time.Parse(time.RFC3339, s); err == nil {
					// Normalize to UTC and reformat in RFC3339
					t[k] = ts.UTC().Format(time.RFC3339)
					continue
				}
			}
			// Recursively process nested structures
			normalizeTimestamps(vv)
		}
	case []interface{}:
		// Process each element in the slice
		for i := range t {
			normalizeTimestamps(t[i])
		}
	}
}

// encodeSorted recursively encodes a value to JSON with sorted keys
//
// This function produces deterministic JSON output by sorting map keys
// alphabetically at all levels. This ensures that the same data structure
// always produces the same JSON string, which is essential for consistent
// hashing in the hash chain.
//
// The function handles:
// - Maps: Sorts keys alphabetically before encoding
// - Slices: Preserves order (slices are already ordered)
// - Primitives: Uses standard JSON marshaling
//
// Args:
//   - buf: Buffer to write JSON to
//   - v: Value to encode
//
// Returns:
//   - Error if encoding fails
func encodeSorted(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case map[string]interface{}:
		// Collect and sort all keys for deterministic output
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Write JSON object with sorted keys
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			// Encode key (strings are safe to marshal directly)
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			// Recursively encode value
			if err := encodeSorted(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []interface{}:
		// Write JSON array (order is preserved)
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			// Recursively encode each element
			if err := encodeSorted(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// Use standard JSON marshaling for primitives
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
		return nil
	}
}

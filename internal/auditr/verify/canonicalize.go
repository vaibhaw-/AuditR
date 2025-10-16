package verify

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"
)

// Canonicalize returns a deterministic JSON string for hashing.
// Rules:
// - Remove hash fields: hash, hash_prev, hash_chain_index
// - Sort keys alphabetically (recursively)
// - Normalize timestamps to UTC RFC3339 when parseable
// - Compact output (no extra whitespace)
func Canonicalize(event map[string]interface{}) (string, error) {
	clean := deepCopyWithoutHashFields(event)
	normalizeTimestamps(clean)
	var buf bytes.Buffer
	if err := encodeSorted(&buf, clean); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func deepCopyWithoutHashFields(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		if k == "hash" || k == "hash_prev" || k == "hash_chain_index" {
			continue
		}
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		m := make(map[string]interface{}, len(t))
		for k, vv := range t {
			m[k] = deepCopyValue(vv)
		}
		return m
	case []interface{}:
		arr := make([]interface{}, len(t))
		for i := range t {
			arr[i] = deepCopyValue(t[i])
		}
		return arr
	default:
		return t
	}
}

func normalizeTimestamps(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, vv := range t {
			// Best-effort RFC3339 parse
			if s, ok := vv.(string); ok {
				if ts, err := time.Parse(time.RFC3339, s); err == nil {
					t[k] = ts.UTC().Format(time.RFC3339)
					continue
				}
			}
			normalizeTimestamps(vv)
		}
	case []interface{}:
		for i := range t {
			normalizeTimestamps(t[i])
		}
	}
}

func encodeSorted(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k) // string key
			buf.Write(kb)
			buf.WriteByte(':')
			if err := encodeSorted(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []interface{}:
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeSorted(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
		return nil
	}
}

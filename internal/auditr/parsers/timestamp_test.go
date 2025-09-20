package parsers

import (
	"testing"
)

// TestNormalizeTimestamp verifies that normalizeTimestamp can parse
// various timestamp formats emitted by Postgres/pgAudit and always
// outputs RFC3339Nano UTC format.
func TestNormalizeTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantUTC string // expected prefix (we only check prefix since Nano precision varies)
	}{
		{
			name:    "UTC without fractional",
			input:   "2025-09-13 14:38:06 UTC",
			wantUTC: "2025-09-13T14:38:06Z",
		},
		{
			name:    "UTC with fractional seconds",
			input:   "2025-09-13 14:38:06.767 UTC",
			wantUTC: "2025-09-13T14:38:06.767",
		},
		{
			name:    "Numeric offset",
			input:   "2025-09-13 14:38:06+05:30",
			wantUTC: "2025-09-13T09:08:06",
		},
		{
			name:    "Numeric offset with fractional",
			input:   "2025-09-13 14:38:06.123+05:30",
			wantUTC: "2025-09-13T09:08:06.123",
		},
		{
			name:    "Named timezone IST",
			input:   "2025-09-13 14:38:06 IST",
			wantUTC: "2025-09-13T09:08:06",
		},
		{
			name:    "RFC3339 format",
			input:   "2025-09-13T14:38:06Z",
			wantUTC: "2025-09-13T14:38:06Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeTimestamp(tt.input)
			if got == "" {
				t.Fatalf("normalizeTimestamp(%q) returned empty string", tt.input)
			}
			if !startsWith(got, tt.wantUTC) {
				t.Errorf("normalizeTimestamp(%q) = %q, want prefix %q", tt.input, got, tt.wantUTC)
			}
		})
	}
}

// startsWith checks if s has prefix p.
func startsWith(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// BenchmarkNormalizeTimestamp compares performance of normalizeTimestamp
// across different formats to understand cost of dateparse.ParseAny.
func BenchmarkNormalizeTimestamp(b *testing.B) {
	samples := []string{
		"2025-09-13 14:38:06 UTC",
		"2025-09-13 14:38:06.767 UTC",
		"2025-09-13 14:38:06+05:30",
		"2025-09-13 14:38:06.123+05:30",
		"2025-09-13 14:38:06 IST",
		"2025-09-13T14:38:06Z",
	}

	for _, sample := range samples {
		b.Run(sample, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = normalizeTimestamp(sample)
			}
		})
	}
}

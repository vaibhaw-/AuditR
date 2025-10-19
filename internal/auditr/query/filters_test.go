package query

import (
	"testing"
	"time"
)

func TestFilterBySensitivity(t *testing.T) {
	tests := []struct {
		name       string
		categories []string
		event      Event
		want       bool
	}{
		{
			name:       "matches PII category",
			categories: []string{"PII"},
			event: Event{
				"sensitivity": []string{"PII:email", "PHI:diagnosis"},
			},
			want: true,
		},
		{
			name:       "matches PHI category",
			categories: []string{"PHI"},
			event: Event{
				"sensitivity": []string{"PII:email", "PHI:diagnosis"},
			},
			want: true,
		},
		{
			name:       "no match for Financial",
			categories: []string{"Financial"},
			event: Event{
				"sensitivity": []string{"PII:email", "PHI:diagnosis"},
			},
			want: false,
		},
		{
			name:       "case insensitive match",
			categories: []string{"pii"},
			event: Event{
				"sensitivity": []string{"PII:email"},
			},
			want: true,
		},
		{
			name:       "no sensitivity field",
			categories: []string{"PII"},
			event: Event{
				"query_type": "SELECT",
			},
			want: false,
		},
		{
			name:       "empty sensitivity array",
			categories: []string{"PII"},
			event: Event{
				"sensitivity": []string{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterBySensitivity(tt.categories)
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterBySensitivity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByUser(t *testing.T) {
	tests := []struct {
		name  string
		user  string
		event Event
		want  bool
	}{
		{
			name: "matches user",
			user: "alice",
			event: Event{
				"db_user": "alice",
			},
			want: true,
		},
		{
			name: "case insensitive match",
			user: "alice",
			event: Event{
				"db_user": "ALICE",
			},
			want: true,
		},
		{
			name: "no match",
			user: "alice",
			event: Event{
				"db_user": "bob",
			},
			want: false,
		},
		{
			name: "no db_user field",
			user: "alice",
			event: Event{
				"query_type": "SELECT",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterByUser(tt.user)
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterByUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByType(t *testing.T) {
	tests := []struct {
		name  string
		types []string
		event Event
		want  bool
	}{
		{
			name:  "matches SELECT",
			types: []string{"SELECT"},
			event: Event{
				"query_type": "SELECT",
			},
			want: true,
		},
		{
			name:  "matches multiple types",
			types: []string{"SELECT", "INSERT"},
			event: Event{
				"query_type": "INSERT",
			},
			want: true,
		},
		{
			name:  "case insensitive match",
			types: []string{"select"},
			event: Event{
				"query_type": "SELECT",
			},
			want: true,
		},
		{
			name:  "no match",
			types: []string{"SELECT"},
			event: Event{
				"query_type": "UPDATE",
			},
			want: false,
		},
		{
			name:  "no query_type field",
			types: []string{"SELECT"},
			event: Event{
				"db_user": "alice",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterByType(tt.types)
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterByType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByBulk(t *testing.T) {
	tests := []struct {
		name  string
		event Event
		want  bool
	}{
		{
			name: "matches bulk true",
			event: Event{
				"bulk": true,
			},
			want: true,
		},
		{
			name: "no match for bulk false",
			event: Event{
				"bulk": false,
			},
			want: false,
		},
		{
			name: "no match for no bulk field",
			event: Event{
				"query_type": "SELECT",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterByBulk()
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterByBulk() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByBulkType(t *testing.T) {
	tests := []struct {
		name     string
		event    Event
		bulkType string
		want     bool
	}{
		{
			name: "matches export type",
			event: Event{
				"bulk_type": "export",
			},
			bulkType: "export",
			want:     true,
		},
		{
			name: "case insensitive match",
			event: Event{
				"bulk_type": "EXPORT",
			},
			bulkType: "export",
			want:     true,
		},
		{
			name: "no match for different type",
			event: Event{
				"bulk_type": "import",
			},
			bulkType: "export",
			want:     false,
		},
		{
			name: "no match for no bulk_type field",
			event: Event{
				"other": "value",
			},
			bulkType: "export",
			want:     false,
		},
		{
			name: "matches backup type",
			event: Event{
				"bulk_type": "backup",
			},
			bulkType: "backup",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterByBulkType(tt.bulkType)
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterByBulkType(%s) = %v, want %v", tt.bulkType, got, tt.want)
			}
		})
	}
}

func TestFilterBySensitiveFields(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		event  Event
		want   bool
	}{
		{
			name:   "matches email field",
			fields: []string{"email"},
			event: Event{
				"sensitivity": []string{"PII:email", "PHI:diagnosis"},
			},
			want: true,
		},
		{
			name:   "matches diagnosis field",
			fields: []string{"diagnosis"},
			event: Event{
				"sensitivity": []string{"PII:email", "PHI:diagnosis"},
			},
			want: true,
		},
		{
			name:   "case insensitive match",
			fields: []string{"EMAIL"},
			event: Event{
				"sensitivity": []string{"PII:email"},
			},
			want: true,
		},
		{
			name:   "no match for ssn",
			fields: []string{"ssn"},
			event: Event{
				"sensitivity": []string{"PII:email", "PHI:diagnosis"},
			},
			want: false,
		},
		{
			name:   "no sensitivity field",
			fields: []string{"email"},
			event: Event{
				"query_type": "SELECT",
			},
			want: false,
		},
		{
			name:   "empty sensitivity array",
			fields: []string{"email"},
			event: Event{
				"sensitivity": []string{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterBySensitiveFields(tt.fields)
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterBySensitiveFields() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByTime(t *testing.T) {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	tests := []struct {
		name  string
		since time.Time
		last  time.Duration
		event Event
		want  bool
	}{
		{
			name:  "matches since time",
			since: oneHourAgo,
			event: Event{
				"timestamp": now.Format(time.RFC3339),
			},
			want: true,
		},
		{
			name:  "no match for since time",
			since: now.Add(1 * time.Hour),
			event: Event{
				"timestamp": now.Format(time.RFC3339),
			},
			want: false,
		},
		{
			name: "matches last duration",
			last: 2 * time.Hour,
			event: Event{
				"timestamp": oneHourAgo.Format(time.RFC3339),
			},
			want: true,
		},
		{
			name: "no match for last duration",
			last: 30 * time.Minute,
			event: Event{
				"timestamp": oneHourAgo.Format(time.RFC3339),
			},
			want: false,
		},
		{
			name:  "invalid timestamp",
			since: oneHourAgo,
			event: Event{
				"timestamp": "invalid",
			},
			want: false,
		},
		{
			name:  "no timestamp field",
			since: oneHourAgo,
			event: Event{
				"query_type": "SELECT",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterByTime(tt.since, tt.last)
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterByTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterExcludeErrors(t *testing.T) {
	tests := []struct {
		name  string
		event Event
		want  bool
	}{
		{
			name: "excludes ERROR type",
			event: Event{
				"query_type": "ERROR",
			},
			want: false,
		},
		{
			name: "includes SELECT type",
			event: Event{
				"query_type": "SELECT",
			},
			want: true,
		},
		{
			name: "case insensitive exclusion",
			event: Event{
				"query_type": "error",
			},
			want: false,
		},
		{
			name: "includes when no query_type field",
			event: Event{
				"db_user": "alice",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := FilterExcludeErrors()
			got := filter(tt.event)
			if got != tt.want {
				t.Errorf("FilterExcludeErrors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchAll(t *testing.T) {
	tests := []struct {
		name    string
		event   Event
		filters []EventFilter
		want    bool
	}{
		{
			name: "all filters match",
			event: Event{
				"db_user":     "alice",
				"query_type":  "SELECT",
				"sensitivity": []string{"PII:email"},
			},
			filters: []EventFilter{
				FilterByUser("alice"),
				FilterByType([]string{"SELECT"}),
				FilterBySensitivity([]string{"PII"}),
			},
			want: true,
		},
		{
			name: "one filter fails",
			event: Event{
				"db_user":     "alice",
				"query_type":  "SELECT",
				"sensitivity": []string{"PII:email"},
			},
			filters: []EventFilter{
				FilterByUser("alice"),
				FilterByType([]string{"INSERT"}), // This will fail
				FilterBySensitivity([]string{"PII"}),
			},
			want: false,
		},
		{
			name: "no filters",
			event: Event{
				"query_type": "SELECT",
			},
			filters: []EventFilter{},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchAll(tt.event, tt.filters)
			if got != tt.want {
				t.Errorf("matchAll() = %v, want %v", got, tt.want)
			}
		})
	}
}

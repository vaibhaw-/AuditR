package parsers

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvent_JSON(t *testing.T) {
	tests := []struct {
		name     string
		event    Event
		wantJSON string
		wantErr  bool
	}{
		{
			name: "Minimal event",
			event: Event{
				EventID:   "123",
				DBSystem:  "postgres",
				QueryType: "SELECT",
			},
			wantJSON: `{"event_id":"123","db_system":"postgres","query_type":"SELECT"}`,
			wantErr:  false,
		},
		{
			name: "Full PostgreSQL event",
			event: Event{
				EventID:       "456",
				Timestamp:     time.Date(2025, 9, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
				DBSystem:      "postgres",
				DBUser:        ptrString("alice"),
				DBName:        ptrString("testdb"),
				ClientIP:      ptrString("10.0.0.1"),
				QueryType:     "SELECT",
				RawQuery:      ptrString("SELECT * FROM users;"),
				AuditClass:    ptrString("READ"),
				SessionID:     ptrInt(42),
				CommandID:     ptrInt(1),
				Action:        ptrString("SELECT"),
				StatementType: ptrString("SELECT"),
				ObjectType:    ptrString("TABLE"),
				ObjectName:    ptrString("users"),
				Enrichment: map[string]interface{}{
					"bulk_operation":  true,
					"bulk_type":       "export",
					"full_table_read": true,
				},
				Meta: map[string]interface{}{
					"record": "12345",
				},
			},
			wantJSON: `{"event_id":"456","timestamp":"2025-09-19T12:00:00Z","db_system":"postgres","db_user":"alice","db_name":"testdb","client_ip":"10.0.0.1","query_type":"SELECT","raw_query":"SELECT * FROM users;","audit_class":"READ","session_id":42,"command_id":1,"action":"SELECT","statement_type":"SELECT","object_type":"TABLE","object_name":"users","enrichment":{"bulk_operation":true,"bulk_type":"export","full_table_read":true},"meta":{"record":"12345"}}`,
			wantErr:  false,
		},
		{
			name: "Full MySQL event",
			event: Event{
				EventID:      "789",
				Timestamp:    time.Date(2025, 9, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
				DBSystem:     "mysql",
				DBUser:       ptrString("bob"),
				DBName:       ptrString("testdb"),
				ClientIP:     ptrString("10.0.0.2"),
				QueryType:    "INSERT",
				RawQuery:     ptrString("INSERT INTO users VALUES (1, 'bob');"),
				ConnectionID: ptrInt(123),
				Status:       ptrInt(0),
				Enrichment: map[string]interface{}{
					"bulk_operation": false,
				},
				Meta: map[string]interface{}{
					"record": "67890",
					"name":   "Query",
				},
			},
			wantJSON: `{"event_id":"789","timestamp":"2025-09-19T12:00:00Z","db_system":"mysql","db_user":"bob","db_name":"testdb","client_ip":"10.0.0.2","query_type":"INSERT","raw_query":"INSERT INTO users VALUES (1, 'bob');","connection_id":123,"status":0,"enrichment":{"bulk_operation":false},"meta":{"name":"Query","record":"67890"}}`,
			wantErr:  false,
		},
		{
			name: "Optional fields omitted",
			event: Event{
				EventID:   "abc",
				DBSystem:  "postgres",
				QueryType: "SELECT",
				DBUser:    ptrString("alice"),
				// All other fields omitted
			},
			wantJSON: `{"event_id":"abc","db_system":"postgres","db_user":"alice","query_type":"SELECT"}`,
			wantErr:  false,
		},
		{
			name: "Empty strings become null",
			event: Event{
				EventID:   "def",
				DBSystem:  "mysql",
				QueryType: "INSERT",
				DBUser:    ptrString(""), // Empty string should become null
				DBName:    ptrString(""), // Empty string should become null
			},
			wantJSON: `{"event_id":"def","db_system":"mysql","query_type":"INSERT"}`,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			got, err := json.Marshal(&tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.wantJSON {
				t.Errorf("json.Marshal() = %v, want %v", string(got), tt.wantJSON)
			}

			// Unmarshal (round-trip test)
			if !tt.wantErr {
				var unmarshaled Event
				err := json.Unmarshal([]byte(tt.wantJSON), &unmarshaled)
				if err != nil {
					t.Errorf("json.Unmarshal() error = %v", err)
					return
				}

				// Compare fields that should match exactly
				if unmarshaled.EventID != tt.event.EventID {
					t.Errorf("EventID after round-trip = %v, want %v", unmarshaled.EventID, tt.event.EventID)
				}
				if unmarshaled.DBSystem != tt.event.DBSystem {
					t.Errorf("DBSystem after round-trip = %v, want %v", unmarshaled.DBSystem, tt.event.DBSystem)
				}
				if unmarshaled.QueryType != tt.event.QueryType {
					t.Errorf("QueryType after round-trip = %v, want %v", unmarshaled.QueryType, tt.event.QueryType)
				}

				// Compare pointer fields
				if !strPtrEqual(unmarshaled.DBUser, tt.event.DBUser) {
					t.Errorf("DBUser after round-trip = %v, want %v", unmarshaled.DBUser, tt.event.DBUser)
				}
				if !strPtrEqual(unmarshaled.DBName, tt.event.DBName) {
					t.Errorf("DBName after round-trip = %v, want %v", unmarshaled.DBName, tt.event.DBName)
				}
				if !strPtrEqual(unmarshaled.ClientIP, tt.event.ClientIP) {
					t.Errorf("ClientIP after round-trip = %v, want %v", unmarshaled.ClientIP, tt.event.ClientIP)
				}
			}
		})
	}
}

// Helper function to compare string pointers
func strPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// Helper function to create int pointer
func ptrInt(i int) *int {
	return &i
}

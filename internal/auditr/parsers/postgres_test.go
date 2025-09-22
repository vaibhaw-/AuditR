package parsers

import (
	"context"
	"strings"
	"testing"
)

func TestPostgresParser_ParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		emitRaw  bool
		wantType string // expected QueryType
		wantUser *string
		wantDB   *string
		wantErr  bool
	}{
		// NOTE: pgAudit does not emit JSON logs. This test is disabled.
		// {
		// 	name:     "JSON log with SELECT",
		// 	line:     `{"timestamp":"2025-09-19T12:00:00Z","user":"alice","db":"salesdb","query":"SELECT * FROM customers;"}`,
		// 	emitRaw:  true,
		// 	wantType: "SELECT",
		// 	wantUser: ptrString("alice"),
		// 	wantDB:   ptrString("salesdb"),
		// 	wantErr:  false,
		// },
		{
			name:     "pgAudit INSERT line",
			line:     `2025-09-13 14:38:06.767 UTC [8547] LOG:  AUDIT: SESSION,47,1,WRITE,INSERT,,, "INSERT INTO patients (id, name) VALUES (1, 'Bob');",<not logged>`,
			emitRaw:  true,
			wantType: "INSERT",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Auth connection authorized",
			line:     `2025-09-19 12:01:00 UTC [1234] LOG:  connection authorized: user=carol database=warehouse`,
			emitRaw:  false,
			wantType: "LOGIN_SUCCESS",
			wantUser: ptrString("carol"),
			wantDB:   ptrString("warehouse"),
			wantErr:  false,
		},
		{
			name:     "Auth connection failed",
			line:     `2025-09-19 12:02:00 UTC [1234] LOG:  connection failed for user=dave`,
			emitRaw:  false,
			wantType: "LOGIN_FAILURE",
			wantUser: ptrString("dave"),
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Auth disconnection",
			line:     `2025-09-19 12:03:00 UTC [1234] LOG:  disconnection: session time: 0:00:01. user=erin database=finance`,
			emitRaw:  true,
			wantType: "LOGOUT",
			wantUser: ptrString("erin"),
			wantDB:   ptrString("finance"),
			wantErr:  false,
		},
		{
			name:     "Non-SQL line",
			line:     `SOME NOISY BACKGROUND MESSAGE`,
			emitRaw:  false,
			wantType: "",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  true, // expect ErrSkipLine
		},
		{
			name:     "pgAudit line with object_type and object_name",
			line:     `2025-09-13 14:40:00.000 UTC [8547] LOG:  AUDIT: SESSION,50,3,WRITE,ALTER,TABLE,customers, "ALTER TABLE customers ADD COLUMN email text;",<not logged>`,
			emitRaw:  true,
			wantType: "ALTER",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "CSV log with comment-prefixed SELECT",
			line:     `2025-09-13 15:55:03.426 UTC [9310] LOG:  AUDIT: SESSION,2,1,READ,SELECT,,, "/* run_id=pg_demo001 op=select sensitivity=sensitive_only user=appuser2 ts=2025-09-13T10:25:03Z */ SELECT p.patient_id FROM healthcare.patient p WHERE p.patient_id = $1 LIMIT 5",<not logged>`,
			emitRaw:  true,
			wantType: "SELECT",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "COPY FROM CSV",
			line:     `2025-09-13 16:00:00.000 UTC [1234] LOG:  AUDIT: SESSION,10,1,WRITE,COPY,TABLE,patients,"COPY patients FROM '/tmp/file.csv' WITH CSV",<not logged>`,
			emitRaw:  true,
			wantType: "COPY",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "COPY TO CSV (export)",
			line:     `2025-09-13 16:05:00.000 UTC [1235] LOG:  AUDIT: SESSION,11,1,READ,COPY,TABLE,patients,"COPY patients TO '/tmp/file.csv' WITH CSV",<not logged>`,
			emitRaw:  true,
			wantType: "COPY",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "SELECT INTO file",
			line:     `2025-09-13 16:10:00.000 UTC [1236] LOG:  AUDIT: SESSION,12,1,READ,SELECT,TABLE,orders,"SELECT * FROM orders INTO OUTFILE '/tmp/orders.csv'",<not logged>`,
			emitRaw:  true,
			wantType: "SELECT_INTO_OUTFILE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Full-table SELECT without WHERE",
			line:     `2025-09-13 16:15:00.000 UTC [1237] LOG:  AUDIT: SESSION,13,1,READ,SELECT,TABLE,customers,"SELECT * FROM customers",<not logged>`,
			emitRaw:  true,
			wantType: "SELECT",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Quoted CREATE INDEX",
			line:     `2025-09-13 16:20:00.000 UTC [1238] LOG:  AUDIT: SESSION,14,1,DDL,CREATE INDEX,INDEX,healthcare.idx_demo,"CREATE INDEX idx_demo ON healthcare.patient(id);",<not logged>`,
			emitRaw:  true,
			wantType: "CREATE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name: "Multi-line CREATE TABLE",
			line: `2025-09-13 16:25:00.000 UTC [1239] LOG:  AUDIT: SESSION,15,1,DDL,CREATE TABLE,TABLE,healthcare.audit_log,"CREATE TABLE healthcare.audit_log (
				id SERIAL PRIMARY KEY,
				event_time TIMESTAMP WITH TIME ZONE,
				user_id TEXT,
				action TEXT
			);",<not logged>`,
			emitRaw:  true,
			wantType: "CREATE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name: "Multi-line INSERT with comments",
			line: `2025-09-13 16:30:00.000 UTC [1240] LOG:  AUDIT: SESSION,16,1,WRITE,INSERT,TABLE,healthcare.audit_log,"/* Audit event
			 * Type: User action
			 * Source: Web UI
			 */
			INSERT INTO healthcare.audit_log (
				event_time,
				user_id,
				action
			) VALUES (
				NOW(),
				'alice',
				'login'
			);",<not logged>`,
			emitRaw:  true,
			wantType: "INSERT",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &PostgresParser{opts: ParserOptions{EmitRaw: tt.emitRaw}}
			evt, err := parser.ParseLine(ctx, tt.line)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if evt.QueryType != tt.wantType {
				t.Errorf("got QueryType=%s, want %s", evt.QueryType, tt.wantType)
			}
			if strings.Contains(tt.name, "comment-prefixed") {
				if evt.RawQuery == nil || !strings.Contains(*evt.RawQuery, "SELECT p.patient_id") {
					t.Errorf("expected RawQuery to contain SELECT, got %v", evt.RawQuery)
				}
			}
			// Only check DBUser if explicitly expected
			if tt.wantUser != nil {
				if evt.DBUser == nil || *evt.DBUser != *tt.wantUser {
					t.Errorf("%s: got DBUser=%v, want %v", tt.name, evt.DBUser, tt.wantUser)
				}
			}

			// Only check DBName if explicitly expected
			if tt.wantDB != nil {
				if evt.DBName == nil || *evt.DBName != *tt.wantDB {
					t.Errorf("%s: got DBName=%v, want %v", tt.name, evt.DBName, tt.wantDB)
				}
			}

			if tt.emitRaw && evt.RawQuery == nil {
				t.Errorf("expected RawQuery to be set")
			}

			if strings.Contains(tt.name, "object_type") {
				if evt.Meta == nil {
					t.Errorf("expected Meta to be populated, got nil")
				} else {
					if evt.Meta["object_type"] != "TABLE" {
						t.Errorf("expected Meta.object_type=TABLE, got %v", evt.Meta["object_type"])
					}
					if evt.Meta["object_name"] != "customers" {
						t.Errorf("expected Meta.object_name=customers, got %v", evt.Meta["object_name"])
					}
				}
			}

		})
	}
}

func TestParsePgAuditCSV(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		expect map[string]string
	}{
		{
			name: "Basic INSERT line",
			line: `2025-09-13 14:38:06.767 UTC [8547] LOG:  AUDIT: SESSION,47,1,WRITE,INSERT,,, "INSERT INTO patients (id, name) VALUES (1, 'Bob');",<not logged>`,
			expect: map[string]string{
				"audit_class":    "SESSION",
				"session_id":     "47",
				"command_id":     "1",
				"action":         "WRITE",
				"statement_type": "INSERT",
			},
		},
		{
			name: "Line with commas in SQL",
			line: `2025-09-13 14:38:07.000 UTC [8547] LOG:  AUDIT: SESSION,48,2,WRITE,INSERT,,, "INSERT INTO patients (id, name, ssn) VALUES (1, 'Bob', '111-22-3333');",<not logged>`,
			expect: map[string]string{
				"audit_class":    "SESSION",
				"session_id":     "48",
				"command_id":     "2",
				"action":         "WRITE",
				"statement_type": "INSERT",
			},
		},
		{
			name:   "Malformed CSV (not enough fields)",
			line:   `2025-09-13 14:38:08.000 UTC [8547] LOG:  AUDIT: BADLINE`,
			expect: nil,
		},
		{
			name:   "No AUDIT prefix",
			line:   `2025-09-13 14:38:09.000 UTC [8547] LOG: some random line`,
			expect: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePgAuditCSV(tt.line)

			if tt.expect == nil && got != nil {
				t.Errorf("expected nil, got %v", got)
				return
			}
			if tt.expect != nil && got == nil {
				t.Errorf("expected %v, got nil", tt.expect)
				return
			}

			for k, want := range tt.expect {
				if got[k] != want {
					t.Errorf("for key %s, got %s, want %s", k, got[k], want)
				}
			}
		})
	}
}

func TestDetectBulkOperation(t *testing.T) {
	tests := []struct {
		name string
		line string
		want struct {
			isBulk    bool
			bulkType  string
			fullTable bool
		}
	}{
		{
			name: "COPY TO CSV",
			line: `2025-09-13 16:35:00.000 UTC [1241] LOG:  AUDIT: SESSION,17,1,READ,COPY,TABLE,healthcare.patients,"COPY healthcare.patients TO '/tmp/patients.csv' WITH (FORMAT CSV, HEADER);",<not logged>`,
			want: struct {
				isBulk    bool
				bulkType  string
				fullTable bool
			}{true, "export", true},
		},
		{
			name: "COPY FROM CSV",
			line: `2025-09-13 16:36:00.000 UTC [1242] LOG:  AUDIT: SESSION,18,1,WRITE,COPY,TABLE,healthcare.patients,"COPY healthcare.patients FROM '/tmp/patients.csv' WITH (FORMAT CSV, HEADER);",<not logged>`,
			want: struct {
				isBulk    bool
				bulkType  string
				fullTable bool
			}{true, "import", false},
		},
		{
			name: "Multi-row INSERT",
			line: `2025-09-13 16:37:00.000 UTC [1243] LOG:  AUDIT: SESSION,19,1,WRITE,INSERT,TABLE,healthcare.patients,"INSERT INTO healthcare.patients (id, name) VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Carol');",<not logged>`,
			want: struct {
				isBulk    bool
				bulkType  string
				fullTable bool
			}{true, "insert", false},
		},
		{
			name: "Full table SELECT",
			line: `2025-09-13 16:38:00.000 UTC [1244] LOG:  AUDIT: SESSION,20,1,READ,SELECT,TABLE,healthcare.patients,"SELECT * FROM healthcare.patients;",<not logged>`,
			want: struct {
				isBulk    bool
				bulkType  string
				fullTable bool
			}{true, "export", true},
		},
		{
			name: "Regular SELECT with WHERE",
			line: `2025-09-13 16:39:00.000 UTC [1245] LOG:  AUDIT: SESSION,21,1,READ,SELECT,TABLE,healthcare.patients,"SELECT * FROM healthcare.patients WHERE id = 1;",<not logged>`,
			want: struct {
				isBulk    bool
				bulkType  string
				fullTable bool
			}{false, "", false},
		},
	}

	parser := &PostgresParser{opts: ParserOptions{EmitRaw: true}}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, err := parser.ParseLine(ctx, tt.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if evt.Enrichment == nil {
				if tt.want.isBulk {
					t.Errorf("expected bulk operation enrichment, got nil")
				}
				return
			}

			gotBulk, _ := evt.Enrichment["bulk_operation"].(bool)
			gotType, _ := evt.Enrichment["bulk_type"].(string)
			gotFull, _ := evt.Enrichment["full_table_read"].(bool)

			if gotBulk != tt.want.isBulk {
				t.Errorf("bulk_operation = %v, want %v", gotBulk, tt.want.isBulk)
			}
			if gotType != tt.want.bulkType {
				t.Errorf("bulk_type = %v, want %v", gotType, tt.want.bulkType)
			}
			if gotFull != tt.want.fullTable {
				t.Errorf("full_table_read = %v, want %v", gotFull, tt.want.fullTable)
			}
		})
	}
}

func TestParseJSONLine(t *testing.T) {
	parser := &PostgresParser{opts: ParserOptions{EmitRaw: true}}

	tests := []struct {
		name     string
		line     string
		wantType string
		wantUser *string
		wantDB   *string
		wantErr  bool
	}{
		{
			name:     "Simple SELECT with user/db",
			line:     `{"timestamp":"2025-09-19T12:00:00Z","user":"alice","db":"salesdb","host":"10.0.0.1","query":"SELECT * FROM customers;"}`,
			wantType: "SELECT",
			wantUser: ptrString("alice"),
			wantDB:   ptrString("salesdb"),
			wantErr:  false,
		},
		{
			name:     "Not JSON",
			line:     `SOME NON-JSON LINE`,
			wantType: "",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  true, // parser returns ErrSkipLine
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, err := parser.parseJSONLine(tt.line)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if evt.QueryType != tt.wantType {
				t.Errorf("got QueryType=%s, want %s", evt.QueryType, tt.wantType)
			}
			if tt.wantUser != nil && (evt.DBUser == nil || *evt.DBUser != *tt.wantUser) {
				t.Errorf("got DBUser=%v, want %v", evt.DBUser, tt.wantUser)
			}
			if tt.wantDB != nil && (evt.DBName == nil || *evt.DBName != *tt.wantDB) {
				t.Errorf("got DBName=%v, want %v", evt.DBName, tt.wantDB)
			}
			if parser.opts.EmitRaw && evt.RawQuery == nil {
				t.Errorf("expected RawQuery to be set when EmitRaw is true")
			}
		})
	}
}

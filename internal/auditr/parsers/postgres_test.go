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
		// Test cases for unquoted SQL in pgAudit CSV (fixes regression where these were skipped)
		{
			name:     "Unquoted CREATE EXTENSION in pgAudit CSV",
			line:     `2025-09-07 12:59:28.420 IST [8997] LOG:  AUDIT: SESSION,1,1,DDL,CREATE EXTENSION,,,CREATE EXTENSION pgaudit;,<not logged>`,
			emitRaw:  true,
			wantType: "CREATE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted SHOW statement in pgAudit CSV",
			line:     `2025-09-07 13:00:11.342 IST [8997] LOG:  AUDIT: SESSION,2,1,MISC,SHOW,,,SHOW shared_preload_libraries;,<not logged>`,
			emitRaw:  true,
			wantType: "SHOW",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted SELECT with COUNT in pgAudit CSV",
			line:     `2025-09-13 14:51:18.070 IST [8675] LOG:  AUDIT: SESSION,2,1,READ,SELECT,,,SELECT COUNT(*) FROM healthcare.patient;,<not logged>`,
			emitRaw:  true,
			wantType: "SELECT",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted CREATE ROLE in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,CREATE ROLE,,,CREATE ROLE auditor LOGIN;,<not logged>`,
			emitRaw:  true,
			wantType: "CREATE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted DROP ROLE in pgAudit CSV",
			line:     `2025-09-07 13:00:42.042 IST [8997] LOG:  AUDIT: SESSION,4,1,ROLE,DROP ROLE,,,DROP ROLE auditor;,<not logged>`,
			emitRaw:  true,
			wantType: "DROP",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted CREATE DATABASE in pgAudit CSV",
			line:     `2025-09-13 14:18:18.531 IST [8118] LOG:  AUDIT: SESSION,2,1,DDL,CREATE DATABASE,,,CREATE DATABASE practicumdb;,<not logged>`,
			emitRaw:  true,
			wantType: "CREATE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted DROP SCHEMA in pgAudit CSV",
			line:     `2025-09-13 14:27:02.069 IST [8184] LOG:  AUDIT: SESSION,1,1,DDL,DROP SCHEMA,,,DROP SCHEMA IF EXISTS healthcare CASCADE;,<not logged>`,
			emitRaw:  true,
			wantType: "DROP",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Mixed format: quoted SQL with comment prefix (already working)",
			line:     `2025-09-13 15:55:03.428 IST [9307] LOG:  AUDIT: SESSION,6,1,WRITE,UPDATE,,,"/* run_id=pg_demo001 op=update sensitivity=mixed user=appuser4 ts=2025-09-13T10:25:03Z */ UPDATE pharmacy.pharmacy_order SET status=$1, total_price=$2 WHERE order_id=$3",<not logged>`,
			emitRaw:  true,
			wantType: "UPDATE",
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "Unquoted DO block in pgAudit CSV",
			line:     `2025-09-13 14:27:02.090 IST [8184] LOG:  AUDIT: SESSION,8,1,FUNCTION,DO,,,DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'appuser1') THEN CREATE ROLE appuser1 LOGIN PASSWORD 'password1'; END IF; END$$;,<not logged>`,
			emitRaw:  true,
			wantType: "EXEC", // DO blocks are classified as EXEC
			wantUser: nil,
			wantDB:   nil,
			wantErr:  false,
		},
		{
			name:     "pgAudit CSV with empty fields and unquoted SQL",
			line:     `2025-09-13 16:00:00.000 IST [9999] LOG:  AUDIT: SESSION,10,5,READ,SELECT,,,SELECT * FROM test_table WHERE id = 1;,<not logged>`,
			emitRaw:  true,
			wantType: "SELECT",
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

// TestParsePgAuditCSVWithQuery tests the new function that extracts SQL queries from pgAudit CSV
func TestParsePgAuditCSVWithQuery(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectOK    bool
		expectQuery string
	}{
		{
			name:        "Unquoted SQL in pgAudit CSV",
			line:        `2025-09-07 12:59:28.420 IST [8997] LOG:  AUDIT: SESSION,1,1,DDL,CREATE EXTENSION,,,CREATE EXTENSION pgaudit;,<not logged>`,
			expectOK:    true,
			expectQuery: "CREATE EXTENSION pgaudit;",
		},
		{
			name:        "Quoted SQL in pgAudit CSV",
			line:        `2025-09-13 15:55:03.428 IST [9307] LOG:  AUDIT: SESSION,6,1,WRITE,UPDATE,,,"/* comment */ UPDATE table SET col=$1",<not logged>`,
			expectOK:    true,
			expectQuery: `/* comment */ UPDATE table SET col=$1`, // CSV parser strips the quotes
		},
		{
			name:        "Complex unquoted SQL with semicolon",
			line:        `2025-09-13 14:51:18.070 IST [8675] LOG:  AUDIT: SESSION,2,1,READ,SELECT,,,SELECT COUNT(*) FROM healthcare.patient;,<not logged>`,
			expectOK:    true,
			expectQuery: "SELECT COUNT(*) FROM healthcare.patient;",
		},
		{
			name:        "No AUDIT prefix",
			line:        `2025-09-13 14:51:18.070 IST [8675] LOG:  Some other log message`,
			expectOK:    false,
			expectQuery: "",
		},
		{
			name:        "Not enough CSV fields",
			line:        `2025-09-13 14:51:18.070 IST [8675] LOG:  AUDIT: SESSION,1`,
			expectOK:    false,
			expectQuery: "",
		},
		{
			name:        "pgAudit CSV without query field",
			line:        `2025-09-13 14:51:18.070 IST [8675] LOG:  AUDIT: SESSION,1,1,READ,SELECT,,,`,
			expectOK:    true,
			expectQuery: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePgAuditCSVWithQuery(tt.line)

			if !tt.expectOK {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("expected non-nil result, got nil")
				return
			}

			gotQuery := result["query"]
			if gotQuery != tt.expectQuery {
				t.Errorf("expected query %q, got %q", tt.expectQuery, gotQuery)
			}

			// Verify other fields are parsed correctly
			if result["audit_class"] != "SESSION" {
				t.Errorf("expected audit_class=SESSION, got %s", result["audit_class"])
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

			gotBulk := evt.Bulk != nil && *evt.Bulk
			gotType := ""
			if evt.BulkType != nil {
				gotType = *evt.BulkType
			}
			gotFull := evt.FullTableRead != nil && *evt.FullTableRead

			if !gotBulk && tt.want.isBulk {
				t.Errorf("expected bulk operation, got nil")
				return
			}

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

func TestPostgresParser_PrivilegeEscalation(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		emitRaw  bool
		wantType string
		wantErr  bool
	}{
		// PostgreSQL privilege escalation via GRANT
		{
			name:     "GRANT ROLE in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,GRANT,,,GRANT ROLE admin TO user1;,<not logged>`,
			emitRaw:  true,
			wantType: "GRANT_ESCALATION",
			wantErr:  false,
		},
		{
			name:     "GRANT WITH ADMIN OPTION in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,GRANT,,,GRANT SELECT ON table TO user WITH ADMIN OPTION;,<not logged>`,
			emitRaw:  true,
			wantType: "GRANT_ESCALATION",
			wantErr:  false,
		},
		{
			name:     "GRANT WITH GRANT OPTION in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,GRANT,,,GRANT SELECT ON table TO user WITH GRANT OPTION;,<not logged>`,
			emitRaw:  true,
			wantType: "GRANT_ESCALATION",
			wantErr:  false,
		},

		// PostgreSQL privilege escalation via REVOKE
		{
			name:     "REVOKE ROLE in pgAudit CSV",
			line:     `2025-09-07 13:00:42.042 IST [8997] LOG:  AUDIT: SESSION,4,1,ROLE,REVOKE,,,REVOKE ROLE admin FROM user1;,<not logged>`,
			emitRaw:  true,
			wantType: "REVOKE_ESCALATION",
			wantErr:  false,
		},

		// PostgreSQL privilege escalation via ALTER ROLE
		{
			name:     "ALTER ROLE WITH SUPER in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,ALTER ROLE,,,ALTER ROLE admin WITH SUPER;,<not logged>`,
			emitRaw:  true,
			wantType: "ALTER_ROLE_ESCALATION",
			wantErr:  false,
		},
		{
			name:     "ALTER ROLE WITH CREATEDB in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,ALTER ROLE,,,ALTER ROLE admin WITH CREATEDB;,<not logged>`,
			emitRaw:  true,
			wantType: "ALTER_ROLE_ESCALATION",
			wantErr:  false,
		},
		{
			name:     "ALTER ROLE WITH CREATEROLE in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,ALTER ROLE,,,ALTER ROLE admin WITH CREATEROLE;,<not logged>`,
			emitRaw:  true,
			wantType: "ALTER_ROLE_ESCALATION",
			wantErr:  false,
		},

		// Non-escalation privilege commands (should remain normal types)
		{
			name:     "GRANT without escalation in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,GRANT,,,GRANT SELECT ON table TO user;,<not logged>`,
			emitRaw:  true,
			wantType: "GRANT",
			wantErr:  false,
		},
		{
			name:     "REVOKE without escalation in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,REVOKE,,,REVOKE SELECT ON table FROM user;,<not logged>`,
			emitRaw:  true,
			wantType: "REVOKE",
			wantErr:  false,
		},
		{
			name:     "ALTER ROLE without escalation in pgAudit CSV",
			line:     `2025-09-07 13:00:42.038 IST [8997] LOG:  AUDIT: SESSION,3,1,ROLE,ALTER ROLE,,,ALTER ROLE user1 PASSWORD 'secret';,<not logged>`,
			emitRaw:  true,
			wantType: "ALTER",
			wantErr:  false,
		},
	}

	parser := NewPostgresParser(ParserOptions{EmitRaw: true})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, err := parser.ParseLine(context.Background(), tt.line)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if evt == nil {
				t.Fatal("ParseLine returned nil event")
			}
			if evt.QueryType != tt.wantType {
				t.Errorf("got QueryType=%s, want %s", evt.QueryType, tt.wantType)
			}
			if tt.emitRaw && evt.RawQuery == nil {
				t.Errorf("expected RawQuery to be set when EmitRaw is true")
			}
		})
	}
}

package parsers

import (
	"context"
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
		{
			name:     "JSON log with SELECT",
			line:     `{"timestamp":"2025-09-19T12:00:00Z","user":"alice","db":"salesdb","query":"SELECT * FROM customers;"}`,
			emitRaw:  true,
			wantType: "SELECT",
			wantUser: ptrString("alice"),
			wantDB:   ptrString("salesdb"),
			wantErr:  false,
		},
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
			if (evt.DBUser == nil && tt.wantUser != nil) ||
				(evt.DBUser != nil && tt.wantUser == nil) ||
				(evt.DBUser != nil && tt.wantUser != nil && *evt.DBUser != *tt.wantUser) {
				t.Errorf("got DBUser=%v, want %v", evt.DBUser, tt.wantUser)
			}
			if (evt.DBName == nil && tt.wantDB != nil) ||
				(evt.DBName != nil && tt.wantDB == nil) ||
				(evt.DBName != nil && tt.wantDB != nil && *evt.DBName != *tt.wantDB) {
				t.Errorf("got DBName=%v, want %v", evt.DBName, tt.wantDB)
			}
			if tt.emitRaw && evt.RawQuery == nil {
				t.Errorf("expected RawQuery to be set")
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

func TestParseJSONLine(t *testing.T) {
	parser := &PostgresParser{opts: ParserOptions{EmitRaw: true}}

	tests := []struct {
		name     string
		line     string
		wantType string
		wantUser *string
		wantDB   *string
		wantIP   *string
		wantErr  bool
	}{
		{
			name:     "Simple SELECT with user/db",
			line:     `{"timestamp":"2025-09-19T12:00:00Z","user":"alice","db":"salesdb","host":"10.0.0.1","query":"SELECT * FROM customers;"}`,
			wantType: "SELECT",
			wantUser: ptrString("alice"),
			wantDB:   ptrString("salesdb"),
			wantIP:   ptrString("10.0.0.1"),
			wantErr:  false,
		},
		{
			name:     "Uses 'username' instead of 'user'",
			line:     `{"timestamp":"2025-09-19T12:05:00Z","username":"bob","db":"accounts","query":"INSERT INTO orders (id) VALUES (1);"}`,
			wantType: "INSERT",
			wantUser: ptrString("bob"),
			wantDB:   ptrString("accounts"),
			wantIP:   nil,
			wantErr:  false,
		},
		{
			name:     "Missing db field",
			line:     `{"timestamp":"2025-09-19T12:10:00Z","user":"carol","query":"UPDATE patients SET name='X' WHERE id=1;"}`,
			wantType: "UPDATE",
			wantUser: ptrString("carol"),
			wantDB:   nil,
			wantIP:   nil,
			wantErr:  false,
		},
		{
			name:     "Not JSON",
			line:     `SOME NON-JSON LINE`,
			wantType: "",
			wantUser: nil,
			wantDB:   nil,
			wantIP:   nil,
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
			if (evt.DBUser == nil && tt.wantUser != nil) ||
				(evt.DBUser != nil && tt.wantUser == nil) ||
				(evt.DBUser != nil && tt.wantUser != nil && *evt.DBUser != *tt.wantUser) {
				t.Errorf("got DBUser=%v, want %v", evt.DBUser, tt.wantUser)
			}
			if (evt.DBName == nil && tt.wantDB != nil) ||
				(evt.DBName != nil && tt.wantDB == nil) ||
				(evt.DBName != nil && tt.wantDB != nil && *evt.DBName != *tt.wantDB) {
				t.Errorf("got DBName=%v, want %v", evt.DBName, tt.wantDB)
			}
			if (evt.ClientIP == nil && tt.wantIP != nil) ||
				(evt.ClientIP != nil && tt.wantIP == nil) ||
				(evt.ClientIP != nil && tt.wantIP != nil && *evt.ClientIP != *tt.wantIP) {
				t.Errorf("got ClientIP=%v, want %v", evt.ClientIP, tt.wantIP)
			}
			if parser.opts.EmitRaw && evt.RawQuery == nil {
				t.Errorf("expected RawQuery to be set when EmitRaw is true")
			}
		})
	}
}

var sqlClassificationTests = []struct {
	name string
	sql  string
	want string
}{
	// Transactions
	{"Begin TX", "BEGIN;", "TX_BEGIN"},
	{"Commit TX", "COMMIT;", "TX_COMMIT"},
	{"Rollback TX", "ROLLBACK;", "TX_ROLLBACK"},

	// DML
	{"Simple SELECT", "SELECT * FROM customers;", "SELECT"},
	{"Nested SELECT", "SELECT id FROM (SELECT id FROM orders) sub;", "SELECT"},
	{"INSERT single", "INSERT INTO patients (id, name) VALUES (1, 'Bob');", "INSERT"},
	{"INSERT multi-row", "INSERT INTO patients (id, name) VALUES (1, 'Bob'), (2, 'Alice');", "INSERT"},
	{"UPDATE", "UPDATE patients SET name='X' WHERE id=1;", "UPDATE"},
	{"DELETE", "DELETE FROM patients WHERE id=1;", "DELETE"},

	// DDL
	{"CREATE TABLE", "CREATE TABLE test (id int);", "CREATE"},
	{"ALTER TABLE", "ALTER TABLE test ADD COLUMN name text;", "ALTER"},
	{"DROP TABLE", "DROP TABLE test;", "DROP"},

	// Privileges
	{"GRANT", "GRANT SELECT ON patients TO alice;", "GRANT"},
	{"REVOKE", "REVOKE SELECT ON patients FROM alice;", "REVOKE"},

	// Bulk / Utility
	{"COPY TO", "COPY patients TO '/tmp/patients.csv' CSV;", "COPY"},
	{"COPY FROM", "COPY patients FROM '/tmp/patients.csv' CSV;", "COPY"},
	{"LOAD DATA", "LOAD DATA INFILE '/tmp/data.csv' INTO TABLE patients;", "LOAD_DATA"},
	{"SELECT INTO OUTFILE", "SELECT * FROM patients INTO OUTFILE '/tmp/patients.csv';", "SELECT_INTO_OUTFILE"},

	// Other
	{"SET statement", "SET search_path TO myschema;", "SET"},
	{"Unknown", "FOO BAR BAZ;", "ANON"},
}

func TestDetectQueryTypeVarious(t *testing.T) {
	for _, tt := range sqlClassificationTests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectQueryType(tt.sql)
			if got != tt.want {
				t.Errorf("detectQueryType(%q) = %s, want %s", tt.sql, got, tt.want)
			}
		})
	}
}

func TestParseLineVarious(t *testing.T) {
	parser := &PostgresParser{opts: ParserOptions{EmitRaw: true}}
	ctx := context.Background()

	for _, tt := range sqlClassificationTests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate a minimal pgAudit log line with the SQL in quotes
			line := `2025-09-20 10:00:00 UTC [1234] LOG:  AUDIT: SESSION,1,1,WRITE,` + tt.want + `,,, "` + tt.sql + `",<not logged>`

			evt, err := parser.ParseLine(ctx, line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if evt.QueryType != tt.want {
				t.Errorf("ParseLine: got QueryType=%s, want %s", evt.QueryType, tt.want)
			}
			if evt.RawQuery == nil || *evt.RawQuery != tt.sql {
				t.Errorf("ParseLine: expected RawQuery=%q, got %v", tt.sql, evt.RawQuery)
			}
		})
	}
}

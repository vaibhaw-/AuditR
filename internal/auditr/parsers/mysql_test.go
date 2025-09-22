package parsers

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertDBUser(t *testing.T, got *string, want *string) {
	t.Helper()
	if want != nil {
		if got == nil || *got != *want {
			t.Errorf("DBUser = %v, want %v", got, want)
		}
	}
}

func assertDBName(t *testing.T, got *string, want *string) {
	t.Helper()
	if want != nil {
		if got == nil || *got != *want {
			t.Errorf("DBName = %v, want %v", got, want)
		}
	}
}

// Sample JSON line from your audit.log (simplified)
const sampleJSON = `{"audit_record":{
	"name":"Query",
	"record":"6432_2025-09-13T09:34:19Z_0",
	"timestamp":"2025-09-13T09:34:19Z",
	"command_class":"select",
	"connection_id":"8",
	"status":0,
	"sqltext":"select @@version_comment limit 1",
	"user":"root[root] @ localhost []",
	"host":"localhost",
	"os_user":"tester",
	"ip":"",
	"db":"testdb"
}}`

// Sample XML line
const sampleXML = `<AUDIT_RECORD NAME="Query" TIMESTAMP="2025-09-13T09:34:19Z" COMMAND_CLASS="insert" CONNECTION_ID="42" STATUS="0" SQLTEXT="INSERT INTO patients VALUES (1,'Alice')" USER="bob[bob] @ 127.0.0.1 []" HOST="127.0.0.1" IP="127.0.0.1" DB="clinic" RECORD="12345"/>`

func TestMySQLParser_ConnectionID(t *testing.T) {
	p := NewMySQLParser(ParserOptions{EmitRaw: false})

	line := `{"audit_record":{
		"name":"Query",
		"record":"300",
		"timestamp":"2025-09-21T12:30:00Z",
		"command_class":"select",
		"connection_id":"12345",
		"status":0,
		"sqltext":"SELECT 1",
		"user":"carol[carol] @ 127.0.0.1 []",
		"host":"127.0.0.1",
		"ip":"127.0.0.1",
		"db":"testdb"
	}}`

	evt, err := p.ParseLine(context.Background(), line)
	if err != nil {
		t.Fatalf("ParseLine error: %v", err)
	}
	if evt == nil {
		t.Fatal("ParseLine returned nil event")
	}

	if evt.ConnectionID == nil || *evt.ConnectionID != 12345 {
		t.Errorf("ConnectionID = %v, want 12345", evt.ConnectionID)
	}
	if evt.Status == nil || *evt.Status != 0 {
		t.Errorf("Status = %v, want 0", evt.Status)
	}
	if evt.QueryType != "SELECT" {
		t.Errorf("QueryType = %q, want SELECT", evt.QueryType)
	}
}

func TestMySQLParser_ConnectionID_XML(t *testing.T) {
	p := NewMySQLParser(ParserOptions{EmitRaw: true}) // 🔥 enable raw query

	line := `<AUDIT_RECORD 
		NAME="Query"
		RECORD="301"
		TIMESTAMP="2025-09-21T12:35:00Z"
		COMMAND_CLASS="update"
		CONNECTION_ID="54321"
		STATUS="0"
		SQLTEXT="UPDATE patients SET name='Eve' WHERE id=1"
		USER="dave[dave] @ 127.0.0.1 []"
		HOST="127.0.0.1"
		IP="127.0.0.1"
		DB="clinic"
	/>`

	evt, err := p.ParseLine(context.Background(), line)
	if err != nil {
		t.Fatalf("ParseLine error: %v", err)
	}
	if evt == nil {
		t.Fatal("ParseLine returned nil event")
	}

	if evt.ConnectionID == nil || *evt.ConnectionID != 54321 {
		t.Errorf("ConnectionID = %v, want 54321", evt.ConnectionID)
	}
	if evt.Status == nil || *evt.Status != 0 {
		t.Errorf("Status = %v, want 0", evt.Status)
	}
	if evt.QueryType != "UPDATE" {
		t.Errorf("QueryType = %q, want UPDATE", evt.QueryType)
	}
	if evt.RawQuery == nil || *evt.RawQuery != "UPDATE patients SET name='Eve' WHERE id=1" {
		t.Errorf("RawQuery = %v, want UPDATE patients …", evt.RawQuery)
	}
}

func TestMySQLParser_BulkOps(t *testing.T) {
	cases := []struct {
		sql      string
		wantBulk bool
		wantType string
	}{
		{"LOAD DATA INFILE '/tmp/file' INTO TABLE t;", true, "import"},
		{"SELECT * FROM users INTO OUTFILE '/tmp/file';", true, "export"},
		{"SELECT 'hi' INTO DUMPFILE '/tmp/file';", true, "export"},
		{"INSERT INTO users VALUES (1,'a'),(2,'b');", true, "insert"},
		{"SELECT * FROM users;", true, "export"}, // full table scan
	}

	p := NewMySQLParser(ParserOptions{EmitRaw: false})

	for _, c := range cases {
		rec := map[string]interface{}{
			"timestamp":     "2025-09-21T10:00:00Z",
			"command_class": "query",
			"sqltext":       c.sql,
			"user":          "u[u] @ localhost []",
			"db":            "d",
		}
		evt := p.eventFromPerconaJSON(rec)
		if c.wantBulk {
			if evt.Enrichment == nil || evt.Enrichment["bulk_operation"] != true {
				t.Errorf("sql=%q expected bulk_operation true", c.sql)
			}
			if evt.Enrichment["bulk_type"] != c.wantType {
				t.Errorf("sql=%q expected bulk_type %q got %v", c.sql, c.wantType, evt.Enrichment["bulk_type"])
			}
		} else if evt.Enrichment != nil {
			t.Errorf("sql=%q expected no enrichment, got %v", c.sql, evt.Enrichment)
		}
	}
}

func TestMySQLParser_ErrorCases(t *testing.T) {
	p := NewMySQLParser(ParserOptions{EmitRaw: false})

	// Non-audit JSON (valid JSON but not an audit_record)
	if evt, err := p.ParseLine(context.Background(), `{"foo":"bar"}`); err != ErrSkipLine || evt != nil {
		t.Errorf("expected ErrSkipLine for non-audit JSON, got evt=%v err=%v", evt, err)
	}

	// Non-JSON, non-XML
	if evt, err := p.ParseLine(context.Background(), "garbage text"); err != ErrSkipLine || evt != nil {
		t.Errorf("expected ErrSkipLine, got evt=%v err=%v", evt, err)
	}
}

func TestMySQLParser_ConnectQuit(t *testing.T) {
	p := NewMySQLParser(ParserOptions{EmitRaw: false})

	connectLine := `{"audit_record":{
		"name":"Connect",
		"record":"100",
		"timestamp":"2025-09-21T11:00:00Z",
		"command_class":"connect",
		"connection_id":"55",
		"status":0,
		"user":"alice[alice] @ 10.0.0.1 []",
		"host":"10.0.0.1",
		"ip":"10.0.0.1",
		"db":"sales"
	}}`

	quitLine := `{"audit_record":{
		"name":"Quit",
		"record":"101",
		"timestamp":"2025-09-21T11:05:00Z",
		"command_class":"quit",
		"connection_id":"55",
		"status":0,
		"user":"alice[alice] @ 10.0.0.1 []",
		"host":"10.0.0.1",
		"ip":"10.0.0.1",
		"db":"sales"
	}}`

	// --- Connect ---
	evt, err := p.ParseLine(context.Background(), connectLine)
	if err != nil {
		t.Fatalf("ParseLine(connect) error: %v", err)
	}
	if evt.QueryType != "LOGIN_SUCCESS" {
		t.Errorf("Connect QueryType = %q, want LOGIN_SUCCESS", evt.QueryType)
	}
	if evt.DBUser == nil || *evt.DBUser != "alice" {
		t.Errorf("Connect DBUser = %v, want alice", evt.DBUser)
	}
	if evt.DBName == nil || *evt.DBName != "sales" {
		t.Errorf("Connect DBName = %v, want sales", evt.DBName)
	}
	if evt.ConnectionID == nil || *evt.ConnectionID != 55 {
		t.Errorf("Connect ConnectionID = %v, want 55", evt.ConnectionID)
	}

	// --- Quit ---
	evt, err = p.ParseLine(context.Background(), quitLine)
	if err != nil {
		t.Fatalf("ParseLine(quit) error: %v", err)
	}
	if evt.QueryType != "LOGOUT" {
		t.Errorf("Quit QueryType = %q, want LOGOUT", evt.QueryType)
	}
	if evt.DBUser == nil || *evt.DBUser != "alice" {
		t.Errorf("Quit DBUser = %v, want alice", evt.DBUser)
	}
	if evt.DBName == nil || *evt.DBName != "sales" {
		t.Errorf("Quit DBName = %v, want sales", evt.DBName)
	}
	if evt.ConnectionID == nil || *evt.ConnectionID != 55 {
		t.Errorf("Quit ConnectionID = %v, want 55", evt.ConnectionID)
	}
}

func TestMySQLParser_CommandClassError(t *testing.T) {
	p := NewMySQLParser(ParserOptions{EmitRaw: true})

	// Case 1: error with SQL text (falls back to detectQueryType)
	errorWithSQL := `{"audit_record":{
		"name":"Query",
		"record":"200",
		"timestamp":"2025-09-21T12:00:00Z",
		"command_class":"error",
		"connection_id":"77",
		"status":1064,
		"sqltext":"INSERT INTO bad_table VALUES (1)",
		"user":"eve[eve] @ 192.168.0.5 []",
		"host":"192.168.0.5",
		"ip":"192.168.0.5",
		"db":"testdb"
	}}`

	evt, err := p.ParseLine(context.Background(), errorWithSQL)
	if err != nil {
		t.Fatalf("ParseLine(errorWithSQL) error: %v", err)
	}
	if evt.QueryType != "INSERT" {
		t.Errorf("QueryType = %q, want INSERT", evt.QueryType)
	}
	if evt.Status == nil || *evt.Status != 1064 {
		t.Errorf("Status = %v, want 1064", evt.Status)
	}
	if evt.RawQuery == nil || *evt.RawQuery != "INSERT INTO bad_table VALUES (1)" {
		t.Errorf("RawQuery = %v, want INSERT INTO bad_table VALUES (1)", evt.RawQuery)
	}

	// Case 2: error without SQL text (should fall back to ANON)
	errorNoSQL := `{"audit_record":{
		"name":"Query",
		"record":"201",
		"timestamp":"2025-09-21T12:05:00Z",
		"command_class":"error",
		"connection_id":"78",
		"status":1064,
		"user":"eve[eve] @ 192.168.0.5 []",
		"host":"192.168.0.5",
		"ip":"192.168.0.5",
		"db":"testdb"
	}}`

	evt, err = p.ParseLine(context.Background(), errorNoSQL)
	if err != nil {
		t.Fatalf("ParseLine(errorNoSQL) error: %v", err)
	}
	if evt.QueryType != "ANON" {
		t.Errorf("QueryType = %q, want ANON", evt.QueryType)
	}
	if evt.Status == nil || *evt.Status != 1064 {
		t.Errorf("Status = %v, want 1064", evt.Status)
	}
}

// Integration test: parse real audit.log fixture
func TestMySQLParser_Integration(t *testing.T) {
	// Adjust the path if needed — assumes audit.log is in testdata/
	logPath := filepath.Join("testdata", "audit.log")

	f, err := os.Open(logPath)
	if err != nil {
		t.Skipf("skipping integration test, file not found: %v", err)
	}
	defer f.Close()

	p := NewMySQLParser(ParserOptions{EmitRaw: true})

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		evt, err := p.ParseLine(context.Background(), line)
		if err == ErrSkipLine {
			continue // skip non-audit lines
		}
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if evt == nil {
			t.Fatalf("nil event returned for line: %s", line)
		}

		// Basic assertions
		if evt.EventID == "" {
			t.Errorf("missing EventID in event: %+v", evt)
		}
		if evt.Timestamp == "" {
			t.Errorf("missing Timestamp in event: %+v", evt)
		}
		if evt.DBSystem != "mysql" {
			t.Errorf("DBSystem = %q, want mysql", evt.DBSystem)
		}

		count++
		if count > 20 {
			break // sample only first 20 events to keep test fast
		}
	}

	if count == 0 {
		t.Errorf("integration test parsed zero events from %s", logPath)
	}
}

func TestMySQLParser_SQLClassification_Table(t *testing.T) {
	cases := []struct {
		name     string
		format   string // "json" or "xml"
		sql      string
		wantType string
	}{
		// Basic DML
		{"Simple SELECT (JSON)", "json", "SELECT * FROM users;", "SELECT"},
		{"INSERT (JSON)", "json", "INSERT INTO patients VALUES (1,'Alice');", "INSERT"},
		{"UPDATE (XML)", "xml", "UPDATE patients SET name='Bob' WHERE id=1", "UPDATE"},
		{"DELETE (JSON)", "json", "DELETE FROM patients WHERE id=3;", "DELETE"},
		{"Truncate (XML)", "xml", "TRUNCATE TABLE tmp;", "DELETE"}, // normalized as DELETE

		// Comment-prefixed queries
		{"Commented SELECT (JSON)", "json", "/* note */ SELECT * FROM patients;", "SELECT"},
		{"Commented INSERT (JSON)", "json", "/* note */ INSERT INTO t VALUES (1);", "INSERT"},
		{"Commented UPDATE (XML)", "xml", "/* change */ UPDATE patients SET name='Eve' WHERE id=2", "UPDATE"},

		// Bulk operations
		{"LOAD DATA (JSON)", "json", "LOAD DATA INFILE '/tmp/file' INTO TABLE t;", "LOAD_DATA"},
		{"SELECT INTO OUTFILE (JSON)", "json", "SELECT * FROM users INTO OUTFILE '/tmp/file';", "SELECT_INTO_OUTFILE"},
		{"SELECT INTO DUMPFILE (JSON)", "json", "SELECT 'hi' INTO DUMPFILE '/tmp/file';", "SELECT_INTO_OUTFILE"},
		{"Multi-row INSERT (XML)", "xml", "INSERT INTO users VALUES (1,'a'),(2,'b');", "INSERT"},

		{"CREATE INDEX (JSON)", "json", "CREATE INDEX idx_demo ON patients(id);", "CREATE"},
		{"CREATE INDEX (XML)", "xml", "CREATE INDEX idx_demo ON patients(id);", "CREATE"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewMySQLParser(ParserOptions{EmitRaw: true})
			var line string

			switch c.format {
			case "json":
				line = fmt.Sprintf(`{"audit_record":{
					"name":"Query",
					"record":"500",
					"timestamp":"2025-09-21T14:00:00Z",
					"command_class":"query",
					"connection_id":"123",
					"status":0,
					"sqltext":"%s",
					"user":"u[u] @ 127.0.0.1 []",
					"host":"127.0.0.1",
					"ip":"127.0.0.1",
					"db":"clinic"
				}}`, c.sql)
			case "xml":
				line = fmt.Sprintf(`<AUDIT_RECORD 
					NAME="Query"
					RECORD="501"
					TIMESTAMP="2025-09-21T14:00:00Z"
					COMMAND_CLASS="query"
					CONNECTION_ID="124"
					STATUS="0"
					SQLTEXT="%s"
					USER="u[u] @ 127.0.0.1 []"
					HOST="127.0.0.1"
					IP="127.0.0.1"
					DB="clinic"
				/>`, c.sql)
			}

			evt, err := p.ParseLine(context.Background(), line)
			if err != nil {
				t.Fatalf("ParseLine error: %v", err)
			}
			if evt == nil {
				t.Fatal("ParseLine returned nil event")
			}

			if evt.QueryType != c.wantType {
				t.Errorf("QueryType = %q, want %q", evt.QueryType, c.wantType)
			}

			// DB and user
			assertDBUser(t, evt.DBUser, ptrString("u"))
			assertDBName(t, evt.DBName, ptrString("clinic"))

			// Raw query contains SQL
			if evt.RawQuery == nil || !strings.Contains(*evt.RawQuery, strings.Fields(c.sql)[0]) {
				t.Errorf("RawQuery = %v, want to contain %q", evt.RawQuery, c.sql)
			}
		})
	}
}

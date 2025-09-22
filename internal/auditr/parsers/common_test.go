package parsers

import (
	"testing"
)

var sqlClassificationTests = []struct {
	name string
	sql  string
	want string
}{
	// --- Transactions ---
	{"Begin", "BEGIN;", "TX_BEGIN"},
	{"Start Transaction", "START TRANSACTION;", "TX_BEGIN"},
	{"Commit", "COMMIT;", "TX_COMMIT"},
	{"Rollback", "ROLLBACK;", "TX_ROLLBACK"},
	{"Savepoint", "SAVEPOINT mysp;", "TX_SAVEPOINT"},
	{"Release Savepoint", "RELEASE SAVEPOINT mysp;", "TX_SAVEPOINT"},

	// --- DML ---
	{"Select", "SELECT * FROM users;", "SELECT"},
	{"Insert", "INSERT INTO users VALUES (1, 'alice');", "INSERT"},
	{"Update", "UPDATE users SET name='bob' WHERE id=1;", "UPDATE"},
	{"Delete", "DELETE FROM users WHERE id=1;", "DELETE"},
	{"Truncate", "TRUNCATE TABLE patients;", "DELETE"},
	{"Replace (MySQL)", "REPLACE INTO patients (id, name) VALUES (1, 'Bob');", "INSERT"},
	{"Merge (Postgres)", "MERGE INTO target USING source ON target.id = source.id;", "MERGE"},

	// --- DDL ---
	{"Create", "CREATE TABLE users (id int);", "CREATE"},
	{"Alter", "ALTER TABLE users ADD COLUMN email text;", "ALTER"},
	{"Drop", "DROP TABLE users;", "DROP"},
	{"Rename Table (MySQL)", "RENAME TABLE old TO new;", "ALTER"},

	// --- Privileges ---
	{"Grant", "GRANT SELECT ON users TO bob;", "GRANT"},
	{"Revoke", "REVOKE SELECT ON users FROM bob;", "REVOKE"},

	// --- Bulk ops ---
	{"Copy", "COPY users TO '/tmp/users.csv';", "COPY"},
	{"Load Data", "LOAD DATA INFILE '/tmp/file' INTO TABLE users;", "LOAD_DATA"},
	{"Select Into Outfile", "SELECT * FROM users INTO OUTFILE '/tmp/file';", "SELECT_INTO_OUTFILE"},
	{"Select Into Dumpfile", "SELECT 'hello' INTO DUMPFILE '/tmp/file';", "SELECT_INTO_OUTFILE"},

	// --- Utility ---
	{"Set", "SET search_path TO myschema;", "SET"},
	{"Reset", "RESET search_path;", "SET"},
	{"Show", "SHOW DATABASES;", "SHOW"},
	{"Vacuum (Postgres)", "VACUUM FULL;", "UTILITY"},
	{"Analyze (Postgres)", "ANALYZE patients;", "UTILITY"},
	{"Comment (Postgres)", "COMMENT ON TABLE patients IS 'test';", "UTILITY"},

	// --- Procedural ---
	{"Call proc", "CALL do_something();", "EXEC"},
	{"Do block (Postgres)", "DO $$ BEGIN RAISE NOTICE 'hi'; END $$;", "EXEC"},
	{"Prepare stmt (MySQL)", "PREPARE stmt FROM 'SELECT 1';", "EXEC"},
	{"Deallocate stmt (MySQL)", "DEALLOCATE PREPARE stmt;", "EXEC"},

	// --- Fallback ---
	{"Unknown", "nonsense text here", "ANON"},

	{"Select with block comment", "/* leading comment */ SELECT * FROM users;", "SELECT"},
	{"Insert with line comment", "-- some note\nINSERT INTO users VALUES (1,'x');", "INSERT"},
}

func TestDetectQueryType(t *testing.T) {
	for _, tt := range sqlClassificationTests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectQueryType(tt.sql)
			if got != tt.want {
				t.Errorf("detectQueryType(%q) = %q, want %q", tt.sql, got, tt.want)
			}
		})
	}
}

func TestLooksLikeSQL(t *testing.T) {
	for _, tt := range sqlClassificationTests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeSQL(tt.sql)
			if tt.want == "ANON" {
				// For ANON cases, looksLikeSQL may return false (acceptable)
				return
			}
			if !got {
				t.Errorf("looksLikeSQL(%q) = false, want true (since expect %q)", tt.sql, tt.want)
			}
		})
	}
}

func TestPtrString(t *testing.T) {
	if got := ptrString("abc"); got == nil || *got != "abc" {
		t.Errorf("ptrString(\"abc\") = %v, want \"abc\"", got)
	}
	if got := ptrString(""); got != nil {
		t.Errorf("ptrString(\"\") = %v, want nil", got)
	}
}

func TestIntPtrFromString(t *testing.T) {
	if got := intPtrFromString("123"); got == nil || *got != 123 {
		t.Errorf("intPtrFromString(\"123\") = %v, want 123", got)
	}
	if got := intPtrFromString(""); got != nil {
		t.Errorf("intPtrFromString(\"\") = %v, want nil", got)
	}
	if got := intPtrFromString("abc"); got != nil {
		t.Errorf("intPtrFromString(\"abc\") = %v, want nil", got)
	}
}

func TestStringOrNil(t *testing.T) {
	// nil input
	if got := stringOrNil(nil); got != nil {
		t.Errorf("stringOrNil(nil) = %v, want nil", got)
	}

	// string input
	if got := stringOrNil("abc"); got == nil || *got != "abc" {
		t.Errorf("stringOrNil(\"abc\") = %v, want \"abc\"", got)
	}
	if got := stringOrNil(""); got != nil {
		t.Errorf("stringOrNil(\"\") = %v, want nil", got)
	}

	// []byte input
	if got := stringOrNil([]byte("xyz")); got == nil || *got != "xyz" {
		t.Errorf("stringOrNil([]byte(\"xyz\")) = %v, want \"xyz\"", got)
	}
	if got := stringOrNil([]byte("")); got != nil {
		t.Errorf("stringOrNil([]byte(\"\")) = %v, want nil", got)
	}

	// int input
	if got := stringOrNil(42); got == nil || *got != "42" {
		t.Errorf("stringOrNil(42) = %v, want \"42\"", got)
	}
}

func TestNormalizeSQL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"   SELECT 1", "SELECT 1"},
		{"/* comment */ SELECT 2", "SELECT 2"},
		{"-- note\nINSERT INTO t VALUES (1)", "INSERT INTO t VALUES (1)"},
		{"/* unterminated", ""},       // safety case
		{"-- whole line comment", ""}, // nothing after comment
	}

	for _, c := range cases {
		got := normalizeSQL(c.in)
		if got != c.want {
			t.Errorf("normalizeSQL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeStmtType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"CREATE INDEX", "CREATE"},
		{"CREATE TABLE", "CREATE"},
		{"ALTER TABLE", "ALTER"},
		{"DROP SCHEMA", "DROP"},
		{"TRUNCATE TABLE patients", "DELETE"},
		{"SELECT", "SELECT"},
		{"", ""},
	}

	for _, c := range cases {
		got := normalizeStmtType(c.in)
		if got != c.want {
			t.Errorf("normalizeStmtType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

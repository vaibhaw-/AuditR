package parsers

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Integration test: parse real Postgres pgAudit fixture
func TestPostgresParser_Integration(t *testing.T) {
	// Assumes you have a small sample log in testdata/postgres_audit.log
	logPath := filepath.Join("testdata", "postgres_audit.log")

	f, err := os.Open(logPath)
	if err != nil {
		t.Skipf("skipping integration test, file not found: %v", err)
	}
	defer f.Close()

	p := NewPostgresParser(ParserOptions{EmitRaw: true})

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		evt, err := p.ParseLine(context.Background(), line)
		if err == ErrSkipLine {
			continue // skip noise
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
		if evt.DBSystem != "postgres" {
			t.Errorf("DBSystem = %q, want postgres", evt.DBSystem)
		}

		count++
		if count > 20 {
			break // sample first 20 events only
		}
	}

	if count == 0 {
		t.Errorf("integration test parsed zero events from %s", logPath)
	}
}

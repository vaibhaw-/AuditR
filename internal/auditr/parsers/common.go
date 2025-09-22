package parsers

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/araddon/dateparse"
)

// normalizeTimestamp tries to parse any timestamp string using dateparse.
// Returns RFC3339Nano UTC format (canonical form for AuditR).
func normalizeTimestamp(s string) string {
	if s == "" {
		return ""
	}
	t, err := dateparse.ParseAny(s)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// looksLikeSQL heuristically determines whether a string appears to be a SQL statement.
// Used to avoid false positives when extracting queries from log lines.
func looksLikeSQL(s string) bool {
	up := strings.ToUpper(strings.TrimSpace(s))

	starters := []string{
		// DML
		"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REPLACE", "MERGE",
		// DDL
		"CREATE", "ALTER", "DROP", "RENAME",
		// TX
		"BEGIN", "START TRANSACTION", "COMMIT", "ROLLBACK",
		"SAVEPOINT", "RELEASE SAVEPOINT",
		// Privileges
		"GRANT", "REVOKE",
		// Bulk
		"COPY", "LOAD DATA",
		// Utility
		"SET", "RESET", "SHOW", "VACUUM", "ANALYZE", "COMMENT",
		// Procedural
		"CALL", "DO", "PREPARE", "DEALLOCATE", "EXEC", "EXECUTE",
	}

	for _, starter := range starters {
		if strings.HasPrefix(up, starter) {
			return true
		}
	}

	// fallback: common SQL tokens
	if strings.Contains(up, " FROM ") ||
		strings.Contains(up, " INTO ") ||
		strings.Contains(up, " VALUES ") {
		return true
	}

	return false
}

// normalizeSQL strips leading comments and whitespace from a SQL string.
// Ensures classification is not blocked by comment headers like /* ... */ or -- ...
func normalizeSQL(query string) string {
	s := strings.TrimSpace(query)

	for {
		switch {
		case strings.HasPrefix(s, "/*"):
			if end := strings.Index(s, "*/"); end != -1 {
				s = strings.TrimSpace(s[end+2:])
				continue
			}
			return "" // unterminated block comment
		case strings.HasPrefix(s, "--"):
			if end := strings.Index(s, "\n"); end != -1 {
				s = strings.TrimSpace(s[end+1:])
				continue
			}
			return "" // whole line was a comment
		}
		break
	}

	return s
}

// normalizeStmtType maps detailed pgAudit statement_type values (e.g., "CREATE INDEX")
// to their canonical counterparts used by AuditR classification.
func normalizeStmtType(s string) string {
	up := strings.ToUpper(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(up, "CREATE"):
		return "CREATE"
	case strings.HasPrefix(up, "ALTER"):
		return "ALTER"
	case strings.HasPrefix(up, "DROP"):
		return "DROP"
	case strings.HasPrefix(up, "TRUNCATE"):
		return "DELETE"
	default:
		return up
	}
}

// detectQueryType inspects the SQL text and classifies it into a canonical type.
func detectQueryType(query string) string {
	s := normalizeSQL(query)
	if s == "" {
		return "ANON"
	}
	sUp := strings.ToUpper(s)

	switch {
	// --- Transaction boundaries ---
	case strings.HasPrefix(sUp, "BEGIN"),
		strings.HasPrefix(sUp, "START TRANSACTION"):
		return "TX_BEGIN"
	case strings.HasPrefix(sUp, "COMMIT"):
		return "TX_COMMIT"
	case strings.HasPrefix(sUp, "ROLLBACK"):
		return "TX_ROLLBACK"
	case strings.HasPrefix(sUp, "SAVEPOINT"),
		strings.HasPrefix(sUp, "RELEASE SAVEPOINT"):
		return "TX_SAVEPOINT"

	// --- Bulk ops (must come before generic SELECT) ---
	case strings.Contains(sUp, "INTO OUTFILE"),
		strings.Contains(sUp, "INTO DUMPFILE"):
		return "SELECT_INTO_OUTFILE"

	// --- DML ---
	case strings.HasPrefix(sUp, "SELECT"):
		return "SELECT"
	case strings.HasPrefix(sUp, "INSERT"):
		return "INSERT"
	case strings.HasPrefix(sUp, "UPDATE"):
		return "UPDATE"
	case strings.HasPrefix(sUp, "DELETE"):
		return "DELETE"
	case strings.HasPrefix(sUp, "TRUNCATE"):
		return "DELETE"
	case strings.HasPrefix(sUp, "REPLACE"):
		return "INSERT"
	case strings.HasPrefix(sUp, "MERGE"):
		return "MERGE"

	// --- DDL ---
	case strings.HasPrefix(sUp, "CREATE"):
		return "CREATE"
	case strings.HasPrefix(sUp, "ALTER"):
		return "ALTER"
	case strings.HasPrefix(sUp, "DROP"):
		return "DROP"
	case strings.HasPrefix(sUp, "RENAME TABLE"):
		return "ALTER"

	// --- Privileges ---
	case strings.HasPrefix(sUp, "GRANT"):
		return "GRANT"
	case strings.HasPrefix(sUp, "REVOKE"):
		return "REVOKE"

	// --- Bulk ops ---
	case strings.HasPrefix(sUp, "COPY"):
		return "COPY"
	case strings.HasPrefix(sUp, "LOAD DATA"):
		return "LOAD_DATA"

	// --- Utility / Session ---
	case strings.HasPrefix(sUp, "SET"),
		strings.HasPrefix(sUp, "RESET"):
		return "SET"
	case strings.HasPrefix(sUp, "SHOW"):
		return "SHOW"
	case strings.HasPrefix(sUp, "ANALYZE"),
		strings.HasPrefix(sUp, "VACUUM"),
		strings.HasPrefix(sUp, "COMMENT"):
		return "UTILITY"

	// --- Procedural / Execution ---
	case strings.HasPrefix(sUp, "CALL"),
		strings.HasPrefix(sUp, "EXEC"),
		strings.HasPrefix(sUp, "EXECUTE"),
		strings.HasPrefix(sUp, "DO"),
		strings.HasPrefix(sUp, "PREPARE"),
		strings.HasPrefix(sUp, "DEALLOCATE"):
		return "EXEC"

	default:
		return "ANON"
	}
}

// ptrString returns a *string or nil for empty input.
func ptrString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func intPtrFromString(s string) *int {
	if s == "" {
		return nil
	}
	if v, err := strconv.Atoi(s); err == nil {
		return &v
	}
	return nil
}

func stringOrNil(v interface{}) *string {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return &s
	case []byte:
		s := strings.TrimSpace(string(t))
		if s == "" {
			return nil
		}
		return &s
	default:
		s := strings.TrimSpace(fmt.Sprint(t))
		if s == "" {
			return nil
		}
		return &s
	}
}

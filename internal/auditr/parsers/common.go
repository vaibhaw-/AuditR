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
	// Normalize SQL to remove leading comments before checking keywords
	normalized := normalizeSQL(s)
	up := strings.ToUpper(strings.TrimSpace(normalized))

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

// isPrivilegeEscalation checks if a GRANT, REVOKE, ALTER USER, CREATE USER, or ALTER ROLE statement
// represents a privilege escalation. This detects high-risk privilege management commands.
//
// Detects:
//   - GRANT ROLE ... TO ... (PostgreSQL role membership grants)
//   - REVOKE ROLE ... FROM ... (PostgreSQL role membership revocations)
//   - GRANT ... WITH ADMIN OPTION (PostgreSQL - allows role administration)
//   - GRANT ... WITH GRANT OPTION (MySQL/PostgreSQL - allows grantee to grant privileges)
//   - GRANT ALL PRIVILEGES (very broad privilege grants)
//   - ALTER USER ... WITH SUPER (MySQL superuser grants)
//   - ALTER USER ... WITH ALL PRIVILEGES (MySQL)
//   - ALTER USER ... WITH GRANT OPTION (MySQL)
//   - CREATE USER ... WITH SUPER (MySQL)
//   - CREATE USER ... WITH GRANT OPTION (MySQL)
//   - ALTER ROLE ... WITH SUPER (PostgreSQL - superuser grants)
//   - ALTER ROLE ... WITH CREATEDB (PostgreSQL - high privilege grants)
//   - ALTER ROLE ... WITH CREATEROLE (PostgreSQL - high privilege grants)
func isPrivilegeEscalation(queryUpper string) bool {
	// GRANT ROLE ... TO ... (PostgreSQL)
	if strings.Contains(queryUpper, "GRANT") && strings.Contains(queryUpper, "ROLE") && strings.Contains(queryUpper, " TO ") {
		return true
	}

	// REVOKE ROLE ... FROM ... (PostgreSQL)
	if strings.Contains(queryUpper, "REVOKE") && strings.Contains(queryUpper, "ROLE") && strings.Contains(queryUpper, " FROM ") {
		return true
	}

	// WITH ADMIN OPTION (PostgreSQL - allows role administration)
	if strings.Contains(queryUpper, "WITH ADMIN OPTION") {
		return true
	}

	// WITH GRANT OPTION (allows grantee to grant privileges to others)
	if strings.Contains(queryUpper, "WITH GRANT OPTION") {
		return true
	}

	// GRANT ALL PRIVILEGES (very broad privilege grants - high risk)
	if strings.Contains(queryUpper, "GRANT") && strings.Contains(queryUpper, "ALL PRIVILEGES") {
		return true
	}

	// ALTER USER ... WITH SUPER/ALL PRIVILEGES/GRANT OPTION (MySQL)
	if strings.HasPrefix(queryUpper, "ALTER USER") {
		if strings.Contains(queryUpper, "WITH SUPER") ||
			strings.Contains(queryUpper, "WITH ALL PRIVILEGES") ||
			strings.Contains(queryUpper, "WITH GRANT OPTION") {
			return true
		}
	}

	// CREATE USER ... WITH SUPER/GRANT OPTION (MySQL)
	if strings.HasPrefix(queryUpper, "CREATE USER") {
		if strings.Contains(queryUpper, "WITH SUPER") ||
			strings.Contains(queryUpper, "WITH GRANT OPTION") {
			return true
		}
	}

	// ALTER ROLE ... WITH SUPER/CREATEDB/CREATEROLE (PostgreSQL)
	if strings.HasPrefix(queryUpper, "ALTER ROLE") {
		if strings.Contains(queryUpper, "WITH SUPER") ||
			strings.Contains(queryUpper, "WITH CREATEDB") ||
			strings.Contains(queryUpper, "WITH CREATEROLE") {
			return true
		}
	}

	return false
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

	// --- DDL (check privilege escalation first) ---
	case strings.HasPrefix(sUp, "CREATE USER"):
		if isPrivilegeEscalation(sUp) {
			return "CREATE_USER_ESCALATION"
		}
		return "CREATE"
	case strings.HasPrefix(sUp, "ALTER USER"):
		if isPrivilegeEscalation(sUp) {
			return "ALTER_USER_ESCALATION"
		}
		return "ALTER"
	case strings.HasPrefix(sUp, "ALTER ROLE"):
		if isPrivilegeEscalation(sUp) {
			return "ALTER_ROLE_ESCALATION"
		}
		return "ALTER"
	case strings.HasPrefix(sUp, "CREATE"):
		return "CREATE"
	case strings.HasPrefix(sUp, "ALTER"):
		return "ALTER"
	case strings.HasPrefix(sUp, "DROP"):
		return "DROP"
	case strings.HasPrefix(sUp, "RENAME TABLE"):
		return "ALTER"

	// --- Privileges (check escalation patterns first) ---
	case strings.HasPrefix(sUp, "GRANT"):
		if isPrivilegeEscalation(sUp) {
			return "GRANT_ESCALATION"
		}
		return "GRANT"
	case strings.HasPrefix(sUp, "REVOKE"):
		if isPrivilegeEscalation(sUp) {
			return "REVOKE_ESCALATION"
		}
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

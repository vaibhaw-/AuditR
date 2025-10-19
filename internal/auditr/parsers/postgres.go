package parsers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// PostgresParser is a parser for pgAudit / Postgres-style audit lines.
// PostgresParser parses pgAudit and Postgres-style audit log lines into structured events.
// It supports both JSON and textual log formats, extracting SQL queries, user info, timestamps, and more.
// The parser is designed to be robust to log format variations and missing fields.
type PostgresParser struct {
	opts ParserOptions
}

// NewPostgresParser constructs a PostgresParser.
func NewPostgresParser(opts ParserOptions) *PostgresParser {
	return &PostgresParser{opts: opts}
}

// Regex to extract query between double quotes in common pgAudit style lines.
// pgAuditQueryRe extracts SQL queries between double quotes in pgAudit log lines.
// Example log:
//
//	2025-09-19 12:00:00 LOG: AUDIT: SESSION,1,1,READ,SELECT,,, "SELECT ssn, name FROM patients WHERE id=42;",<none>
//
// The regex is lazy to avoid over-matching.
// Example:
// 2025-09-19 12:00:00 LOG: AUDIT: SESSION,1,1,READ,SELECT,,, "SELECT ssn, name FROM patients WHERE id=42;",<none>
var pgAuditQueryRe = regexp.MustCompile(`"(?s:(.*?))"(?:,|$)`) // lazy match between quotes

// NOTE: required imports for this function (add to your file's import block if not present):
// import (
//     "context"
//     "encoding/json"
//     "fmt"
//     "strconv"
//     "strings"
//
//     "github.com/google/uuid"
// )

// ParseLine routes to JSON or text parsing depending on log format.
func (p *PostgresParser) ParseLine(ctx context.Context, line string) (*Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, ErrSkipLine
	}

	// NOTE:
	// pgAudit does not natively emit JSON audit events — it only writes CSV-style lines
	// into the PostgreSQL log. This call is commented out to avoid wasting CPU cycles
	// on JSON parsing attempts that will never succeed in current pgAudit versions.
	//
	// The function parseJSONLine is kept in the codebase for potential future use,
	// e.g., if logs are preprocessed into JSON by a collector, or if pgAudit ever
	// adds a native JSON output mode.
	//
	// Try JSON branch first
	// if evt, err := p.parseJSONLine(line); err == nil && evt != nil {
	// 	return evt, nil
	// }

	// Fallback: text/pgAudit branch
	return p.parseTextLine(line)
}

// parseJSONLine handles JSON-formatted Postgres audit logs.
func (p *PostgresParser) parseJSONLine(line string) (*Event, error) {
	var j map[string]interface{}
	if err := json.Unmarshal([]byte(line), &j); err != nil {
		return nil, ErrSkipLine // not JSON → signal caller to try text
	}

	q := extractQueryFromJSON(j)
	if q == "" {
		return nil, ErrSkipLine
	}

	evt := &Event{
		EventID:   uuid.NewString(),
		DBSystem:  "postgres",
		QueryType: detectQueryType(q),
	}

	if ts := extractTimestampFromJSON(j); ts != "" {
		evt.Timestamp = ts
	}
	if u := extractStringField(j, "user"); u != "" {
		evt.DBUser = ptrString(u)
	} else if u2 := extractStringField(j, "username"); u2 != "" {
		evt.DBUser = ptrString(u2)
	}
	if db := extractStringField(j, "db"); db != "" {
		evt.DBName = ptrString(db)
	}
	if host := extractStringField(j, "host"); host != "" {
		evt.ClientIP = ptrString(host)
	}
	if p.opts.EmitRaw {
		evt.RawQuery = ptrString(q)
	}

	// pgAudit CSV fields not present in JSON logs → leave nil
	return evt, nil
}

// parseTextLine handles pgAudit text-format audit logs.
// It supports both standard PostgreSQL log lines and pgAudit-specific CSV format.
// The function follows this process:
// 1. Extract timestamp and normalize line
// 2. Check for authentication events (login/logout)
// 3. Extract SQL query from log line
// 4. Parse pgAudit CSV fields if present
// 5. Detect bulk operations and enrich event
func (p *PostgresParser) parseTextLine(line string) (*Event, error) {
	log := logger.L()

	// Extract timestamp and normalize line
	ts, rest := extractTimestampFromLine(line)
	if ts != "" {
		log.Debugw("extracted timestamp",
			"timestamp", ts,
			"remainder", rest)
	}
	lower := strings.ToLower(line)

	// --- Auth events ---
	// Check for authentication-related events first as they have a different format
	// than regular SQL queries. These include:
	// - Successful logins ("connection authorized")
	// - Failed logins ("connection failed")
	// - Logouts ("disconnection")
	switch {
	case strings.Contains(lower, "connection authorized"):
		log.Debugw("found login success event", "line", line)
		evt := &Event{
			EventID:   uuid.NewString(),
			DBSystem:  "postgres",
			QueryType: "LOGIN_SUCCESS",
			Timestamp: normalizeTimestamp(ts),
		}
		if u := extractUserFromLine(line); u != "" {
			evt.DBUser = ptrString(u)
			log.Debugw("extracted user from login", "user", u)
		}
		if db := extractDBFromLine(line); db != "" {
			evt.DBName = ptrString(db)
			log.Debugw("extracted database from login", "database", db)
		}
		if p.opts.EmitRaw {
			evt.RawQuery = ptrString(line)
		}
		return evt, nil

	case strings.Contains(lower, "connection failed"):
		log.Debugw("found login failure event", "line", line)
		evt := &Event{
			EventID:   uuid.NewString(),
			DBSystem:  "postgres",
			QueryType: "LOGIN_FAILURE",
			Timestamp: normalizeTimestamp(ts),
		}
		if u := extractUserFromLine(line); u != "" {
			evt.DBUser = ptrString(u)
			log.Debugw("extracted user from failed login", "user", u)
		}
		if p.opts.EmitRaw {
			evt.RawQuery = ptrString(line)
		}
		return evt, nil

	case strings.Contains(lower, "disconnection"):
		log.Debugw("found logout event", "line", line)
		evt := &Event{
			EventID:   uuid.NewString(),
			DBSystem:  "postgres",
			QueryType: "LOGOUT",
			Timestamp: normalizeTimestamp(ts),
		}
		if u := extractUserFromLine(line); u != "" {
			evt.DBUser = ptrString(u)
			log.Debugw("extracted user from logout", "user", u)
		}
		if db := extractDBFromLine(line); db != "" {
			evt.DBName = ptrString(db)
			log.Debugw("extracted database from logout", "database", db)
		}
		if p.opts.EmitRaw {
			evt.RawQuery = ptrString(line)
		}
		return evt, nil
	}

	// --- SQL extraction ---
	// Extract SQL query from the log line. We try two methods:
	// 1. Look for quoted SQL in pgAudit CSV format
	// 2. Look for SQL after "statement:" in regular Postgres logs
	q := ""
	log.Debugw("attempting SQL extraction", "line", line)

	// Try pgAudit CSV format first (quoted SQL)
	if matches := pgAuditQueryRe.FindAllStringSubmatch(line, -1); len(matches) > 0 {
		log.Debugw("found potential SQL matches", "count", len(matches))
		for i := len(matches) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(matches[i][1])
			candidate = strings.Trim(candidate, `"`) // strip surrounding quotes if present
			// Skip empty candidates (common in pgAudit logs with empty fields)
			if candidate == "" {
				log.Debugw("skipping empty candidate", "index", i)
				continue
			}
			log.Debugw("checking SQL candidate",
				"index", i,
				"candidate", candidate,
				"looks_like_sql", looksLikeSQL(strings.ToUpper(candidate)))
			if looksLikeSQL(strings.ToUpper(candidate)) {
				q = candidate
				log.Debugw("found valid SQL", "query", q)
				break
			}
		}
	}

	// If no SQL found in quotes, try parsing pgAudit CSV to get the query field
	if q == "" {
		if csvData := parsePgAuditCSVWithQuery(line); csvData != nil {
			if sqlQuery := csvData["query"]; sqlQuery != "" {
				log.Debugw("found SQL in pgAudit CSV field", "query", sqlQuery)
				candidate := strings.TrimSpace(sqlQuery)
				candidate = strings.Trim(candidate, `"`) // strip quotes if present
				if looksLikeSQL(strings.ToUpper(candidate)) {
					q = candidate
					log.Debugw("found valid SQL in CSV field", "query", q)
				}
			}
		}
	}

	// If no SQL found in CSV, try "statement:" prefix
	if q == "" {
		if idx := strings.Index(lower, "statement:"); idx >= 0 {
			log.Debugw("found statement prefix", "position", idx)
			after := strings.TrimSpace(line[idx+len("statement:"):])
			after = strings.Trim(after, `"`) // strip quotes
			after = strings.Trim(after, "\"")
			log.Debugw("checking statement candidate",
				"candidate", after,
				"looks_like_sql", looksLikeSQL(strings.ToUpper(after)))
			if looksLikeSQL(strings.ToUpper(after)) {
				q = after
				log.Debugw("found valid SQL after statement:", "query", q)
			}
		}
	}

	// No SQL found - skip this line
	if q == "" {
		log.Debugw("no SQL query found in line; skipping", "line", line)
		return nil, ErrSkipLine
	}

	evt := &Event{
		EventID:   uuid.NewString(),
		DBSystem:  "postgres",
		QueryType: detectQueryType(q),
		Timestamp: normalizeTimestamp(ts),
	}

	if u := extractUserFromLine(line); u != "" {
		evt.DBUser = ptrString(u)
	}
	if db := extractDBFromLine(line); db != "" {
		evt.DBName = ptrString(db)
	}

	if p.opts.EmitRaw {
		evt.RawQuery = ptrString(q)
	}

	// Check for bulk operations
	if enrichment := detectBulkOperation(q); enrichment != nil {
		if bulk, ok := enrichment["bulk_operation"].(bool); ok && bulk {
			evt.Bulk = &bulk
			if bulkType, ok := enrichment["bulk_type"].(string); ok {
				evt.BulkType = &bulkType
			}
			if fullTable, ok := enrichment["full_table_read"].(bool); ok {
				evt.FullTableRead = &fullTable
			}
		}
	}

	// --- CSV parsing for pgAudit structured fields ---
	if extra := parsePgAuditCSV(line); extra != nil {
		if v := extra["audit_class"]; v != "" {
			evt.AuditClass = ptrString(v)
		}
		if v := extra["session_id"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				evt.SessionID = &n
			}
		}
		if v := extra["command_id"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				evt.CommandID = &n
			}
		}
		if v := extra["action"]; v != "" {
			evt.Action = ptrString(v)
		}
		if v := extra["statement_type"]; v != "" {
			evt.StatementType = ptrString(v)
			if !strings.EqualFold(normalizeStmtType(v), evt.QueryType) {
				logger.L().Warnw("statement_type mismatch",
					"csv", v, "detected", evt.QueryType, "line", line)
			}
		}
		// --- Meta parity: stash extra fields ---
		meta := map[string]interface{}{}
		if v := extra["object_type"]; v != "" {
			meta["object_type"] = v
		}
		if v := extra["object_name"]; v != "" {
			meta["object_name"] = v
		}
		if len(meta) > 0 {
			evt.Meta = meta
		}
	}

	return evt, nil
}

// extractTimestampFromLine tries to pull a plausible timestamp prefix and rest of line.
// extractTimestampFromLine tries to extract a plausible timestamp prefix from a log line.
// Returns the timestamp string and the remainder of the line.
// min returns the smaller of two integers.
func extractTimestampFromLine(line string) (string, string) {
	// typical syslog-style prefix: "2025-09-19 12:00:00 " - try first 19-30 chars
	if len(line) >= 19 {
		prefix := line[:19]
		// try parsing
		if _, err := time.Parse("2006-01-02 15:04:05", prefix); err == nil {
			return prefix, strings.TrimSpace(line[19:])
		}
	}
	// try full token before 'LOG:' or 'AUDIT:'
	if idx := strings.Index(line, "LOG:"); idx > 0 {
		before := strings.TrimSpace(line[:idx])
		parts := strings.Fields(before)
		if len(parts) > 0 {
			// try combinations of first 2 fields
			candidate := strings.Join(parts[:min(len(parts), 2)], " ")
			return candidate, strings.TrimSpace(line[idx:])
		}
	}
	return "", line
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractQueryFromJSON tries to find a SQL string in JSON-structured logs.
// Looks for common keys like 'query', 'statement', 'sql', etc.
func extractQueryFromJSON(j map[string]interface{}) string {
	// common keys: "query", "statement", "sql"
	keys := []string{"query", "statement", "sql", "statement_text", "query_text"}
	for _, k := range keys {
		if v, ok := j[k]; ok {
			if s, ok2 := v.(string); ok2 {
				return strings.TrimSpace(s)
			}
		}
	}
	// some Percona-like JSON use "event":"Query" and "sql":...
	// fallthrough
	return ""
}

// extractTimestampFromJSON tries common timestamp keys and returns normalized RFC3339 string.
// extractTimestampFromJSON tries common timestamp keys in JSON logs and returns normalized RFC3339 string.
// extractStringField returns the string value for a given key in a JSON map, or empty string if not found.
func extractTimestampFromJSON(j map[string]interface{}) string {
	keys := []string{"timestamp", "time", "ts", "log_time", "datetime"}
	for _, k := range keys {
		if v, ok := j[k]; ok {
			switch t := v.(type) {
			case string:
				return normalizeTimestamp(t)
			}
		}
	}
	return ""
}

func extractStringField(j map[string]interface{}, key string) string {
	if v, ok := j[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// extractUserFromLine best-effort: look for 'user=' or 'user:' or 'user "' patterns.
// extractUserFromLine attempts to extract a username from a log line using common patterns.
// Returns the username or empty string if not found.
func extractUserFromLine(line string) string {
	// patterns: user=alice, user: alice, user "alice"
	pats := []string{"user=", "user:", `user "`}
	lower := strings.ToLower(line)
	for _, p := range pats {
		if idx := strings.Index(lower, p); idx >= 0 {
			start := idx + len(p)
			rem := line[start:]
			// trim common separators and quotes
			rem = strings.TrimLeft(rem, ` "'`)
			// get token
			fields := strings.Fields(rem)
			if len(fields) > 0 {
				// strip trailing punctuation
				return strings.Trim(fields[0], `",;`)
			}
		}
	}
	return ""
}

// extractDBFromLine best-effort: look for 'db=' or 'database='
// extractDBFromLine attempts to extract a database name from a log line using common patterns.
// Returns the database name or empty string if not found.
func extractDBFromLine(line string) string {
	pats := []string{"db=", "database=", "db \""}
	lower := strings.ToLower(line)
	for _, p := range pats {
		if idx := strings.Index(lower, p); idx >= 0 {
			start := idx + len(p)
			rem := line[start:]
			rem = strings.TrimLeft(rem, ` "'`)
			fields := strings.Fields(rem)
			if len(fields) > 0 {
				return strings.Trim(fields[0], `",;`)
			}
		}
	}
	return ""
}

// detectBulkOperation checks if a query is a bulk operation and returns enrichment info.
// It looks for several patterns that indicate bulk data operations:
// - COPY TO/FROM: PostgreSQL's native bulk data transfer
// - SELECT INTO OUTFILE/DUMPFILE: MySQL-style data export
// - Multi-row INSERT: Multiple VALUES clauses or multiple value sets
// - Full table SELECT: SELECT without WHERE clause
//
// Multi-row INSERT Detection Logic:
// A bulk INSERT operation is detected when:
// 1. Multiple VALUES clauses: "INSERT ... VALUES (...), VALUES (...)" - rare but possible
// 2. Multiple value sets in single VALUES: "INSERT ... VALUES (1,2), (3,4), (5,6)"
//   - Detected by patterns "),(" or "), (" (with space)
//   - Note: We do NOT use comma counting as single-row INSERTs with many columns
//     can have many commas (e.g., 15 columns = 14 commas) but are not bulk operations
//
// 3. Multiple INSERT statements in one query (handled by VALUES count > 1)
func detectBulkOperation(query string) map[string]interface{} {
	log := logger.L()
	up := strings.ToUpper(query)

	log.Debugw("checking for bulk operation", "query", query)

	// COPY operations
	if strings.Contains(up, "COPY") {
		log.Debugw("found COPY operation")
		if strings.Contains(up, "TO") {
			log.Debugw("detected COPY TO (export)")
			return map[string]interface{}{
				"bulk_operation":  true,
				"bulk_type":       "export",
				"full_table_read": true,
			}
		}
		if strings.Contains(up, "FROM") {
			log.Debugw("detected COPY FROM (import)")
			return map[string]interface{}{
				"bulk_operation": true,
				"bulk_type":      "import",
			}
		}
	}

	// SELECT INTO OUTFILE
	if strings.Contains(up, "INTO OUTFILE") || strings.Contains(up, "INTO DUMPFILE") {
		log.Debugw("detected SELECT INTO OUTFILE/DUMPFILE")
		return map[string]interface{}{
			"bulk_operation":  true,
			"bulk_type":       "export",
			"full_table_read": true,
		}
	}

	// Multi-row INSERT detection
	if strings.HasPrefix(up, "INSERT") && strings.Contains(up, "VALUES") {
		// Count VALUES clauses - multiple VALUES clauses indicate bulk operation
		// Example: "INSERT ... VALUES (...), VALUES (...)" (rare but possible)
		valuesCount := strings.Count(up, "VALUES")

		// Check for multiple value sets within a single VALUES clause
		// Examples: "VALUES (1,2), (3,4), (5,6)" or "VALUES (1,2), (3,4), (5,6)"
		// We check both "),(" and "), (" patterns as SQL formatting varies
		hasMultipleValueSets := strings.Contains(up, "),(") || strings.Contains(up, "), (")

		// A query is considered bulk if it has multiple VALUES clauses OR multiple value sets
		// Note: We deliberately do NOT use comma counting as single-row INSERTs with many
		// columns can have many commas but are not bulk operations
		isMultiRow := hasMultipleValueSets || valuesCount > 1

		log.Debugw("checking INSERT for bulk operation",
			"values_count", valuesCount,
			"has_multiple_value_sets", hasMultipleValueSets,
			"is_multi_row", isMultiRow)

		if isMultiRow {
			log.Debugw("detected multi-row INSERT")
			return map[string]interface{}{
				"bulk_operation": true,
				"bulk_type":      "insert",
			}
		}
	}

	// Full table SELECT - only consider it bulk if it's selecting actual data columns
	if strings.HasPrefix(up, "SELECT") {
		hasWhere := strings.Contains(up, "WHERE")

		// Check if this is a data export (not just metadata/system queries)
		isDataExport := false
		if !hasWhere {
			// Check for SELECT * (wildcard - definitely bulk)
			if strings.Contains(up, "SELECT *") {
				isDataExport = true
			} else {
				// Check for actual column names (not system functions)
				// Extract the column list between SELECT and FROM
				selectFromMatch := regexp.MustCompile(`SELECT\s+(.+?)\s+FROM`).FindStringSubmatch(up)
				if len(selectFromMatch) > 1 {
					columnList := strings.TrimSpace(selectFromMatch[1])
					// Check if it contains actual column names (not just COUNT(*), NOW(), etc.)
					// System functions typically don't have spaces before the function name
					if !regexp.MustCompile(`(?i)^(COUNT|SUM|AVG|MIN|MAX|NOW|VERSION|USER|DATABASE|1|'[^']*')\s*\(?`).MatchString(columnList) {
						isDataExport = true
					}
				}
			}
		}

		log.Debugw("checking SELECT for full table read",
			"has_where", hasWhere,
			"is_data_export", isDataExport)

		if !hasWhere && isDataExport {
			log.Debugw("detected full table SELECT (data export)")
			return map[string]interface{}{
				"bulk_operation":  true,
				"bulk_type":       "export",
				"full_table_read": true,
			}
		}
	}

	log.Debugw("no bulk operation detected")
	return nil
}

// parsePgAuditCSV parses the CSV portion of a pgAudit log line using encoding/csv.
// It returns a map of field name → string, or nil if parsing fails.
func parsePgAuditCSV(line string) map[string]string {
	idx := strings.Index(line, "AUDIT:")
	if idx < 0 {
		return nil
	}
	csvPart := strings.TrimSpace(line[idx+len("AUDIT:"):])

	r := csv.NewReader(strings.NewReader(csvPart))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1

	tokens, err := r.Read()
	if err != nil || len(tokens) < 5 {
		return nil
	}

	result := make(map[string]string)
	result["audit_class"] = strings.TrimSpace(tokens[0])
	result["session_id"] = strings.TrimSpace(tokens[1])
	result["command_id"] = strings.TrimSpace(tokens[2])
	result["action"] = strings.TrimSpace(tokens[3])
	result["statement_type"] = strings.TrimSpace(tokens[4])

	if len(tokens) > 5 {
		result["object_type"] = strings.TrimSpace(tokens[5])
	}
	if len(tokens) > 6 {
		result["object_name"] = strings.TrimSpace(tokens[6])
	}

	return result
}

// parsePgAuditCSVWithQuery parses the CSV portion of a pgAudit log line and extracts the query field.
// It returns a map of field name → string, including the "query" field, or nil if parsing fails.
// This is similar to parsePgAuditCSV but also extracts the SQL query from the 8th CSV field.
func parsePgAuditCSVWithQuery(line string) map[string]string {
	idx := strings.Index(line, "AUDIT:")
	if idx < 0 {
		return nil
	}
	csvPart := strings.TrimSpace(line[idx+len("AUDIT:"):])

	r := csv.NewReader(strings.NewReader(csvPart))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1

	tokens, err := r.Read()
	if err != nil || len(tokens) < 5 {
		return nil
	}

	result := make(map[string]string)
	result["audit_class"] = strings.TrimSpace(tokens[0])
	result["session_id"] = strings.TrimSpace(tokens[1])
	result["command_id"] = strings.TrimSpace(tokens[2])
	result["action"] = strings.TrimSpace(tokens[3])
	result["statement_type"] = strings.TrimSpace(tokens[4])

	if len(tokens) > 5 {
		result["object_type"] = strings.TrimSpace(tokens[5])
	}
	if len(tokens) > 6 {
		result["object_name"] = strings.TrimSpace(tokens[6])
	}
	// Extract the SQL query field (8th field, index 7)
	if len(tokens) > 7 {
		result["query"] = strings.TrimSpace(tokens[7])
	}

	return result
}

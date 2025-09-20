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

// Regex to extract IPv4/IPv6-ish token occurrences (best-effort)
// ipRe matches IPv4 and IPv6-like tokens in log lines (best-effort, not strict validation).
var ipRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})|([0-9a-fA-F:]{3,})`)

// time layouts we try to parse
// timeLayouts lists timestamp formats commonly found in Postgres logs.
// The parser tries each layout in order to normalize timestamps.
var timeLayouts = []string{
	"2006-01-02 15:04:05 MST",   // e.g., "2025-09-19 12:00:00 UTC"
	"2006-01-02 15:04:05 -0700", // with numeric offset
	"2006-01-02 15:04:05",       // common without zone (assume UTC)
	time.RFC3339,                // ISO format if present
	"Jan 2 15:04:05 2006",       // syslog-ish (rare)
}

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

	// Try JSON branch first
	if evt, err := p.parseJSONLine(line); err == nil && evt != nil {
		return evt, nil
	}

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
func (p *PostgresParser) parseTextLine(line string) (*Event, error) {
	log := logger.L()

	ts, _ := extractTimestampFromLine(line)
	lower := strings.ToLower(line)

	// --- Auth events ---
	switch {
	case strings.Contains(lower, "connection authorized"):
		evt := &Event{
			EventID:   uuid.NewString(),
			DBSystem:  "postgres",
			QueryType: "LOGIN_SUCCESS",
			Timestamp: normalizeTimestamp(ts),
		}
		if u := extractUserFromLine(line); u != "" {
			evt.DBUser = ptrString(u)
		}
		if db := extractDBFromLine(line); db != "" {
			evt.DBName = ptrString(db)
		}
		if p.opts.EmitRaw {
			evt.RawQuery = ptrString(line)
		}
		return evt, nil

	case strings.Contains(lower, "connection failed"):
		evt := &Event{
			EventID:   uuid.NewString(),
			DBSystem:  "postgres",
			QueryType: "LOGIN_FAILURE",
			Timestamp: normalizeTimestamp(ts),
		}
		if u := extractUserFromLine(line); u != "" {
			evt.DBUser = ptrString(u)
		}
		if p.opts.EmitRaw {
			evt.RawQuery = ptrString(line)
		}
		return evt, nil

	case strings.Contains(lower, "disconnection"):
		evt := &Event{
			EventID:   uuid.NewString(),
			DBSystem:  "postgres",
			QueryType: "LOGOUT",
			Timestamp: normalizeTimestamp(ts),
		}
		if u := extractUserFromLine(line); u != "" {
			evt.DBUser = ptrString(u)
		}
		if db := extractDBFromLine(line); db != "" {
			evt.DBName = ptrString(db)
		}
		if p.opts.EmitRaw {
			evt.RawQuery = ptrString(line)
		}
		return evt, nil
	}

	// --- SQL extraction ---
	q := ""
	if matches := pgAuditQueryRe.FindAllStringSubmatch(line, -1); len(matches) > 0 {
		for i := len(matches) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(matches[i][1])
			if looksLikeSQL(strings.ToUpper(candidate)) {
				q = candidate
				break
			}
		}
	}
	if q == "" {
		if idx := strings.Index(lower, "statement:"); idx >= 0 {
			after := strings.TrimSpace(line[idx+len("statement:"):])
			after = strings.Trim(after, "\"")
			if looksLikeSQL(strings.ToUpper(after)) {
				q = after
			}
		}
	}
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
	if ip := extractIPFromLine(line); ip != "" {
		evt.ClientIP = ptrString(ip)
	}
	if p.opts.EmitRaw {
		evt.RawQuery = ptrString(q)
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
			if !strings.EqualFold(v, evt.QueryType) {
				logger.L().Warnw("statement_type mismatch",
					"csv", v, "detected", evt.QueryType, "line", line)
			}
		}
	}

	return evt, nil
}

// ptrString returns a *string or nil for empty input.
func ptrString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func detectQueryType(query string) string {
	s := strings.TrimSpace(query)
	if s == "" {
		return "ANON"
	}
	sUp := strings.ToUpper(s)

	switch {
	// Transaction boundaries
	case strings.HasPrefix(sUp, "BEGIN"), strings.HasPrefix(sUp, "START TRANSACTION"):
		return "TX_BEGIN"
	case strings.HasPrefix(sUp, "COMMIT"):
		return "TX_COMMIT"
	case strings.HasPrefix(sUp, "ROLLBACK"):
		return "TX_ROLLBACK"

	// DML
	case strings.HasPrefix(sUp, "SELECT"):
		return "SELECT"
	case strings.HasPrefix(sUp, "INSERT"):
		return "INSERT"
	case strings.HasPrefix(sUp, "UPDATE"):
		return "UPDATE"
	case strings.HasPrefix(sUp, "DELETE"):
		return "DELETE"

	// DDL
	case strings.HasPrefix(sUp, "CREATE"):
		return "CREATE"
	case strings.HasPrefix(sUp, "ALTER"):
		return "ALTER"
	case strings.HasPrefix(sUp, "DROP"):
		return "DROP"

	// Privileges
	case strings.HasPrefix(sUp, "GRANT"):
		return "GRANT"
	case strings.HasPrefix(sUp, "REVOKE"):
		return "REVOKE"

	// Bulk ops
	case strings.HasPrefix(sUp, "COPY"):
		return "COPY"
	case strings.Contains(sUp, "INTO OUTFILE"):
		return "SELECT_INTO_OUTFILE"
	case strings.HasPrefix(sUp, "LOAD DATA"):
		return "LOAD_DATA"

	// Session settings, sometimes important
	case strings.HasPrefix(sUp, "SET"):
		return "SET"

	default:
		return "ANON"
	}
}

// looksLikeSQL is a heuristic to determine whether candidate text appears SQL-like.
// looksLikeSQL heuristically determines whether a string appears to be a SQL statement.
// Used to avoid false positives when extracting queries from log lines.
func looksLikeSQL(up string) bool {
	// check common SQL starters
	starters := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "BEGIN", "COMMIT", "ROLLBACK", "COPY", "GRANT", "REVOKE", "SET"}
	for _, s := range starters {
		if strings.HasPrefix(up, s) {
			return true
		}
	}
	// fallback: contains FROM or INTO or VALUES
	if strings.Contains(up, " FROM ") || strings.Contains(up, " INTO ") || strings.Contains(up, " VALUES ") {
		return true
	}
	return false
}

// normalizeTimestamp takes raw timestamp strings and returns RFC3339 UTC form or empty.
// normalizeTimestamp attempts to parse a raw timestamp string using known layouts and returns RFC3339 UTC format.
// Returns empty string if parsing fails.
func normalizeTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// try layouts
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	// try to parse a prefix like "2025-09-19 12:00:00"
	if len(raw) >= 19 {
		sub := raw[:19]
		if t, err := time.Parse("2006-01-02 15:04:05", sub); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
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

// extractIPFromLine best-effort using regex to find an IP-like token.
// extractIPFromLine uses a regex to find an IP-like token in a log line (best-effort).
// Returns the IP string or empty if not found.
func extractIPFromLine(line string) string {
	if m := ipRe.FindString(line); m != "" {
		return m
	}
	return ""
}

// tryParseAuthEvent inspects a log line for connection/disconnection events.
// tryParseAuthEvent inspects a log line for connection/disconnection events (login, logout, failed login).
// Returns a structured event map if matched, or nil otherwise.
// Returns nil if not matched.
/*
func tryParseAuthEvent(line string, ts string, emitRaw bool) map[string]interface{} {
	lower := strings.ToLower(line)

	switch {
	case strings.Contains(lower, "connection authorized"):
		evt := map[string]interface{}{
			"event_id":   uuid.NewString(),
			"timestamp":  normalizeTimestamp(ts),
			"db_system":  "postgres",
			"query_type": "LOGIN_SUCCESS",
		}
		if u := extractUserFromLine(line); u != "" {
			evt["db_user"] = u
		}
		if db := extractDBFromLine(line); db != "" {
			evt["db_name"] = db
		}
		if emitRaw {
			evt["raw_query"] = line
		}
		return evt

	case strings.Contains(lower, "connection failed"):
		evt := map[string]interface{}{
			"event_id":   uuid.NewString(),
			"timestamp":  normalizeTimestamp(ts),
			"db_system":  "postgres",
			"query_type": "LOGIN_FAILURE",
		}
		if u := extractUserFromLine(line); u != "" {
			evt["db_user"] = u
		}
		if emitRaw {
			evt["raw_query"] = line
		}
		return evt

	case strings.Contains(lower, "disconnection"):
		evt := map[string]interface{}{
			"event_id":   uuid.NewString(),
			"timestamp":  normalizeTimestamp(ts),
			"db_system":  "postgres",
			"query_type": "LOGOUT",
		}
		if u := extractUserFromLine(line); u != "" {
			evt["db_user"] = u
		}
		if db := extractDBFromLine(line); db != "" {
			evt["db_name"] = db
		}
		if emitRaw {
			evt["raw_query"] = line
		}
		return evt
	}

	return nil
}
*/

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

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

package parsers

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// MySQLParser implements Parser for Percona/MySQL audit logs (JSON or XML).
type MySQLParser struct {
	opts ParserOptions
}

// NewMySQLParser constructs a MySQLParser.
func NewMySQLParser(opts ParserOptions) *MySQLParser {
	return &MySQLParser{opts: opts}
}

// ParseLine parses a single line from a Percona audit log.
// Supports audit_log_format=JSON or XML. Returns ErrSkipLine for noise.
// The function follows this process:
// 1. Try parsing as JSON (preferred format)
// 2. Try parsing as XML (fallback format)
// 3. Skip line if neither format matches
func (p *MySQLParser) ParseLine(ctx context.Context, line string) (*Event, error) {
	log := logger.L()
	line = strings.TrimSpace(line)
	if line == "" {
		log.Debugw("skipping empty line")
		return nil, ErrSkipLine
	}

	log.Debugw("parsing MySQL audit line", "length", len(line))

	// --- JSON branch ---
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &wrapper); err == nil {
		log.Debugw("successfully parsed JSON wrapper")
		if rawRec, ok := wrapper["audit_record"]; ok {
			log.Debugw("found audit_record in JSON")
			var rec map[string]interface{}
			if err := json.Unmarshal(rawRec, &rec); err != nil {
				log.Warnw("malformed audit_record JSON",
					"err", err.Error(),
					"line", line)
				return nil, fmt.Errorf("malformed audit_record JSON: %w", err)
			}
			log.Debugw("successfully parsed audit_record",
				"record_type", rec["name"],
				"command_class", rec["command_class"])
			return p.eventFromPerconaJSON(rec), nil
		}
		log.Debugw("JSON wrapper missing audit_record field")
		return nil, ErrSkipLine
	}

	// --- XML branch ---
	log.Debugw("trying XML format")
	var rec auditRecordXML
	if err := xml.Unmarshal([]byte(line), &rec); err == nil && rec.XMLName.Local == "AUDIT_RECORD" {
		log.Debugw("successfully parsed XML audit record",
			"record_name", rec.Name,
			"command_class", rec.CommandClass)
		return p.eventFromPerconaXML(rec), nil
	}

	// Not JSON or XML audit record → skip
	log.Debugw("line is neither valid JSON nor XML audit record", "line", line)
	return nil, ErrSkipLine
}

// auditRecordXML defines Percona's XML audit record attributes.
type auditRecordXML struct {
	XMLName      xml.Name `xml:"AUDIT_RECORD"`
	Name         string   `xml:"NAME,attr"`
	Timestamp    string   `xml:"TIMESTAMP,attr"`
	CommandClass string   `xml:"COMMAND_CLASS,attr"`
	ConnectionID string   `xml:"CONNECTION_ID,attr"`
	Status       string   `xml:"STATUS,attr"`
	SQLText      string   `xml:"SQLTEXT,attr"`
	User         string   `xml:"USER,attr"`
	Host         string   `xml:"HOST,attr"`
	IP           string   `xml:"IP,attr"`
	DB           string   `xml:"DB,attr"`
	Record       string   `xml:"RECORD,attr"`
}

// eventFromPerconaJSON builds an Event from a Percona JSON audit_record.
func (p *MySQLParser) eventFromPerconaJSON(rec map[string]interface{}) *Event {
	getStr := func(k string) string {
		if v, ok := rec[k]; ok && v != nil {
			return strings.TrimSpace(fmt.Sprint(v))
		}
		return ""
	}

	rawTs := getStr("timestamp")
	sql := getStr("sqltext")
	cmdClass := strings.ToLower(getStr("command_class"))
	recName := getStr("name")
	status := intPtrFromString(getStr("status"))

	evt := &Event{
		EventID:   uuid.NewString(),
		DBSystem:  "mysql",
		Timestamp: normalizeTimestamp(rawTs),
		DBUser:    ptrString(extractDBUserFromPerconaUser(getStr("user"))),
		DBName:    ptrString(getStr("db")),
		ClientIP:  chooseIP(getStr("ip"), getStr("host")),
		Status:    status,
		Meta: map[string]interface{}{
			"record":  getStr("record"),
			"name":    recName,
			"os_user": getStr("os_user"),
		},
	}

	// now we can compute QueryType
	evt.QueryType = mapCommandClassToQueryType(cmdClass, sql, recName, status)
	// ConnectionID and Status go to typed fields
	evt.ConnectionID = intPtrFromString(getStr("connection_id"))
	if st := getStr("status"); st != "" {
		evt.Status = intPtrFromString(st)
	}

	// Emit raw query if requested
	if p.opts.EmitRaw && sql != "" {
		evt.RawQuery = &sql
	}

	// Bulk detection
	if bulk, btype, full := detectMySQLBulkOp(sql); bulk {
		bulkVal := true
		evt.Bulk = &bulkVal
		if btype != "" {
			evt.BulkType = &btype
		}
		if full {
			fullVal := true
			evt.FullTableRead = &fullVal
		}
	}

	return evt
}

// eventFromPerconaXML builds an Event from a Percona XML audit_record.
func (p *MySQLParser) eventFromPerconaXML(rec auditRecordXML) *Event {
	status := intPtrFromString(rec.Status)
	evt := &Event{
		EventID:      uuid.NewString(),
		DBSystem:     "mysql",
		Timestamp:    normalizeTimestamp(rec.Timestamp),
		DBUser:       ptrString(extractDBUserFromPerconaUser(rec.User)),
		DBName:       ptrString(rec.DB),
		ClientIP:     chooseIP(rec.IP, rec.Host),
		ConnectionID: intPtrFromString(rec.ConnectionID),
		Status:       status,
		Meta: map[string]interface{}{
			"record":  rec.Record,
			"name":    rec.Name,
			"os_user": "", // Percona XML doesn’t usually have os_user
		},
	}
	evt.QueryType = mapCommandClassToQueryType(rec.CommandClass, rec.SQLText, rec.Name, status)
	evt.ConnectionID = intPtrFromString(rec.ConnectionID)
	if rec.Status != "" {
		evt.Status = intPtrFromString(rec.Status)
	}

	if p.opts.EmitRaw && rec.SQLText != "" {
		evt.RawQuery = &rec.SQLText
	}

	if bulk, btype, full := detectMySQLBulkOp(rec.SQLText); bulk {
		bulkVal := true
		evt.Bulk = &bulkVal
		if btype != "" {
			evt.BulkType = &btype
		}
		if full {
			fullVal := true
			evt.FullTableRead = &fullVal
		}
	}

	return evt
}

// extractDBUserFromPerconaUser parses strings like "root[root] @ localhost []" → "root".
func extractDBUserFromPerconaUser(userField string) string {
	if userField == "" {
		return ""
	}
	if idx := strings.Index(userField, "["); idx > 0 {
		return strings.TrimSpace(userField[:idx])
	}
	parts := strings.Fields(userField)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}

// chooseIP returns ip if set, otherwise host, otherwise nil.
func chooseIP(ip, host string) *string {
	if ip != "" {
		return ptrString(ip)
	}
	if host != "" {
		return ptrString(host)
	}
	return nil
}

func mapCommandClassToQueryType(cmdClass, sql, recName string, status *int) string {
	cmd := strings.ToLower(strings.TrimSpace(cmdClass))
	switch cmd {
	case "select":
		return "SELECT"
	case "insert":
		return "INSERT"
	case "update":
		return "UPDATE"
	case "delete":
		return "DELETE"
	case "create", "create_db", "create_table", "create_index":
		return "CREATE"
	case "alter", "alter_table":
		return "ALTER"
	case "drop", "drop_db", "drop_table":
		return "DROP"
	case "grant":
		return "GRANT"
	case "revoke":
		return "REVOKE"
	case "load_data":
		return "LOAD_DATA"
	case "show": // 🔥 new
		return "SHOW"
	case "prepare", "deallocate": // 🔥 new
		return "EXEC"
	case "connect":
		if status != nil && *status != 0 {
			return "LOGIN_FAILURE"
		}
		return "LOGIN_SUCCESS"

	case "quit":
		return "LOGOUT"
	case "error":
		if sql != "" {
			return detectQueryType(sql)
		}
		return "ANON"
	default:
		// fallback to record name or SQL text
		switch strings.ToLower(strings.TrimSpace(recName)) {
		case "query":
			if sql != "" {
				return detectQueryType(sql)
			}
			return "ANON"
		case "connect":
			return "LOGIN_SUCCESS"
		case "quit":
			return "LOGOUT"
		default:
			if sql != "" {
				return detectQueryType(sql)
			}
			return "ANON"
		}
	}
}

// detectMySQLBulkOp flags bulk operations in SQL.
// It looks for several patterns that indicate bulk data operations:
// - LOAD DATA INFILE: MySQL's native data import
// - INTO OUTFILE/DUMPFILE: MySQL's data export
// - Multi-row INSERT: Multiple value sets or multiple VALUES clauses
// - Full table SELECT: SELECT without WHERE clause
//
// Multi-row INSERT Detection Logic:
// A bulk INSERT operation is detected when:
// 1. Multiple VALUES clauses: "INSERT ... VALUES (...), VALUES (...)" - rare but possible
// 2. Multiple value sets in single VALUES: "INSERT ... VALUES (1,2), (3,4), (5,6)"
//   - Detected by patterns "),(" or "), (" (with space)
//   - Note: We do NOT use comma counting as single-row INSERTs with many columns
//     can have many commas (e.g., 15 columns = 14 commas) but are not bulk operations
func detectMySQLBulkOp(sql string) (bool, string, bool) {
	log := logger.L()

	if sql == "" {
		log.Debugw("empty SQL, not a bulk operation")
		return false, "", false
	}

	up := strings.ToUpper(sql)
	log.Debugw("checking for MySQL bulk operation", "sql", sql)

	// LOAD DATA INFILE
	if strings.Contains(up, "LOAD DATA INFILE") {
		log.Debugw("detected LOAD DATA INFILE (import)")
		return true, "import", false
	}

	// INTO OUTFILE/DUMPFILE
	if strings.Contains(up, "INTO OUTFILE") || strings.Contains(up, "INTO DUMPFILE") {
		log.Debugw("detected INTO OUTFILE/DUMPFILE (export)")
		return true, "export", true
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
			return true, "insert", false
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
			return true, "export", true
		}
	}

	log.Debugw("no bulk operation detected")
	return false, "", false
}

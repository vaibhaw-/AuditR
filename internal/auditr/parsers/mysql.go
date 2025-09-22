package parsers

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
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
		evt.Enrichment = map[string]interface{}{
			"bulk_operation":  true,
			"bulk_type":       btype,
			"full_table_read": full,
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
		evt.Enrichment = map[string]interface{}{
			"bulk_operation":  true,
			"bulk_type":       btype,
			"full_table_read": full,
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
// - Multi-row INSERT: Multiple value sets with ),(
// - Full table SELECT: SELECT without WHERE clause
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

	// Multi-row INSERT
	if strings.HasPrefix(up, "INSERT") {
		hasMultipleValues := strings.Contains(up, "),(")
		log.Debugw("checking INSERT for bulk operation",
			"has_multiple_values", hasMultipleValues)
		if hasMultipleValues {
			log.Debugw("detected multi-row INSERT")
			return true, "insert", false
		}
	}

	// Full table SELECT
	if strings.HasPrefix(up, "SELECT") {
		hasWhere := strings.Contains(up, "WHERE")
		log.Debugw("checking SELECT for full table read",
			"has_where", hasWhere)
		if !hasWhere {
			log.Debugw("detected full table SELECT")
			return true, "export", true
		}
	}

	log.Debugw("no bulk operation detected")
	return false, "", false
}

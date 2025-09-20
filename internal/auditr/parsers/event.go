package parsers

// Event represents a canonical AuditR event emitted by any DB parser.
// It maps directly to the NDJSON schema.
type Event struct {
	EventID   string  `json:"event_id"`
	Timestamp string  `json:"timestamp,omitempty"` // RFC3339 UTC
	DBSystem  string  `json:"db_system"`
	DBUser    *string `json:"db_user"`             // null if unknown
	DBName    *string `json:"db_name"`             // null if unknown
	ClientIP  *string `json:"client_ip,omitempty"` // optional

	QueryType string  `json:"query_type"`
	RawQuery  *string `json:"raw_query,omitempty"` // only if EmitRaw enabled

	// pgAudit-specific structured fields
	AuditClass    *string `json:"audit_class,omitempty"`
	SessionID     *int    `json:"session_id,omitempty"`
	CommandID     *int    `json:"command_id,omitempty"`
	Action        *string `json:"action,omitempty"`
	StatementType *string `json:"statement_type,omitempty"`
	ObjectType    *string `json:"object_type,omitempty"`
	ObjectName    *string `json:"object_name,omitempty"`

	// Future extensions (enrichment step)
	// Sensitivity []string          `json:"sensitivity,omitempty"`
	// RiskLevel   *string           `json:"risk_level,omitempty"`
}

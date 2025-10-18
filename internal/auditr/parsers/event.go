package parsers

// Event represents a canonical AuditR event emitted by any DB parser.
// It maps directly to the NDJSON schema.
type Event struct {
	EventID   string  `json:"event_id"`
	Timestamp string  `json:"timestamp,omitempty"` // RFC3339 UTC
	DBSystem  string  `json:"db_system"`
	DBUser    *string `json:"db_user,omitempty"`   // null if unknown
	DBName    *string `json:"db_name,omitempty"`   // null if unknown
	ClientIP  *string `json:"client_ip,omitempty"` // optional

	QueryType string  `json:"query_type"`
	RawQuery  *string `json:"raw_query,omitempty"` // only if EmitRaw enabled

	// Bulk operation detection (populated by parser)
	Bulk          *bool   `json:"bulk,omitempty"`
	BulkType      *string `json:"bulk_type,omitempty"` // "insert", "export", "import"
	FullTableRead *bool   `json:"full_table_read,omitempty"`

	// pgAudit-specific structured fields (optional, populated only for Postgres)
	AuditClass    *string `json:"audit_class,omitempty"`
	SessionID     *int    `json:"session_id,omitempty"`
	CommandID     *int    `json:"command_id,omitempty"`
	Action        *string `json:"action,omitempty"`
	StatementType *string `json:"statement_type,omitempty"`
	ObjectType    *string `json:"object_type,omitempty"`
	ObjectName    *string `json:"object_name,omitempty"`

	// Percona/MySQL-specific structured fields (optional, populated only for MySQL)
	ConnectionID *int `json:"connection_id,omitempty"`
	Status       *int `json:"status,omitempty"`

	// Enrichment (sensitivity, risk, and other enrichment data)
	Enrichment map[string]interface{} `json:"enrichment,omitempty"`

	// DB-specific extras that don't warrant a first-class field.
	// Examples: Percona "record" ID, "name"; future DB plugin extras.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

# AuditR & LoadR

This repository contains two complementary tools designed for the Practicum capstone project on **Database Audit Logging & Enrichment**:

- **AuditR** → CLI tool for parsing, enriching, verifying, and querying database audit logs (PostgreSQL pgAudit & MySQL Percona Audit Plugin).  
- **LoadR** → Synthetic data + workload generator for PostgreSQL/MySQL, used to produce realistic queries that exercise PII, PHI, and financial data fields.

Together they form a complete demo pipeline:  
**LoadR → Database (pgAudit / Percona) → Audit logs → AuditR → Enriched compliance reports**

## 🚀 Quick Start

```bash
# 1. Build the tools
make

# 2. Generate test data and run workload (see LoadR docs for details)
./bin/loadr load --config cmd/loadr/config/load_pg.yaml
createdb practicumdb && psql -d practicumdb -f seed_pg.sql
./bin/loadr run --config cmd/loadr/config/run_pg.yaml

# 3. Parse audit logs
./bin/auditr parse --db postgres --input /path/to/pgaudit.log --output parsed.ndjson --emit-raw

# 4. Extract schema and enrich with sensitivity detection
psql -d practicumdb -c "SELECT current_database(), schemaname, tablename, attname, format_type(atttypid, atttypmod) FROM pg_attribute a JOIN pg_class c ON a.attrelid = c.oid JOIN pg_namespace n ON c.relnamespace = n.oid JOIN pg_tables t ON c.relname = t.tablename AND n.nspname = t.schemaname WHERE a.attnum > 0 AND NOT a.attisdropped ORDER BY schemaname, tablename, attname;" --csv > schema.csv
./bin/auditr enrich --schema schema.csv --dict cmd/auditr/config/sensitivity_dict_extended.json --risk cmd/auditr/config/risk_scoring.json --input parsed.ndjson --output enriched.ndjson --emit-unknown

# 5. Analyze results
jq '.risk_level' enriched.ndjson | sort | uniq -c
```

**📖 For detailed LoadR setup and configuration, see [LoadR Documentation](docs/loadr.md)**

# 📋 Prerequisites

**AuditR Requirements:**
- PostgreSQL 16 with pgAudit extension installed and enabled
- MySQL 8 with Percona Audit Log Plugin

**LoadR Requirements:**
- See [LoadR Documentation](docs/loadr.md) for detailed setup instructions

# 🚀 LoadR: Data & Workload Generator

LoadR is a synthetic data and workload generator for PostgreSQL and MySQL, used to produce realistic queries that exercise PII, PHI, and financial data fields for testing AuditR's audit log processing capabilities.

**📖 [Complete LoadR Documentation →](docs/loadr.md)**

LoadR provides:
- **Database Schema**: Healthcare, pharmacy, and payments system with realistic relationships and sensitive data types
- **Data Generation**: Synthetic data creation with configurable volume and user simulation
- **Workload Simulation**: Realistic query patterns with sensitivity mix and multi-user concurrency
- **Audit Log Generation**: Annotated queries that produce comprehensive audit logs for testing

# 🔍 AuditR: Audit Log Enricher
AuditR is a CLI tool that processes database audit logs into tamper-evident, enriched compliance reports.

## Features

* **Parse** PostgreSQL pgAudit or MySQL Percona Audit Log Plugin logs
* **Normalize** into NDJSON format with structured event data
* **Detect** bulk operations (multi-row INSERT, data export SELECT, COPY, LOAD DATA) automatically during parsing
* **Enrich** with schema metadata, sensitivity classification, and risk scoring
* **Classify** sensitive data (PII, PHI, Financial) using regex-based dictionaries
* **Score** risk levels (low, medium, high, critical) based on data combinations
* **Handle errors** gracefully - never lose data, emit structured ERROR events
* **Log comprehensively** with configurable output levels and run summaries
* **Support** both PostgreSQL and MySQL audit log formats

## Logging Configuration

AuditR provides flexible logging configuration to help with debugging and monitoring:

### Log Levels

* **debug**: Detailed information for troubleshooting
* **info**: General operational information (default)
* **warn**: Warning conditions
* **error**: Error conditions that should be investigated

### Log Outputs

* **Console**: Always enabled, with configurable minimum level
* **Debug File**: Optional JSON file for all debug and above logs
* **Info File**: Optional JSON file for info and above logs
* **Run Log**: Append-only JSONL file for run summaries

### Example Configuration

```yaml
logging:
  # Minimum log level for all outputs
  level: "info"
  # Minimum level for console output (can be higher than file level)
  console_level: "info"
  # Debug log file (optional) - includes all debug level and above logs
  debug_file: "./logs/debug.jsonl"
  # Info log file (optional) - includes all info level and above logs
  info_file: "./logs/info.jsonl"
  # Run summary log file - append-only JSONL
  run_log: "./logs/run_log.jsonl"
  # Development mode enables more verbose output
  development: true
```

### Debug Features

When troubleshooting, you can enable debug logging to see:

* **Parser Details**:
  - SQL query extraction and classification
  - Bulk operation detection (COPY, LOAD DATA, multi-row INSERT, data export SELECT)
  - Authentication events
  - Parsing decisions and context
  - Column resolution and schema matching

* **Processing Stats**:
  - Progress updates every 1000 lines
  - Lines processed per second
  - Parse success/reject ratios
  - Run duration and summary

* **File Operations**:
  - Input/output file handling
  - Reject file operations
  - Run log updates

### Example Debug Output

```
2025-09-22T10:00:00.000Z DEBUG attempting SQL extraction {"line_length": 256}
2025-09-22T10:00:00.001Z DEBUG found potential SQL matches {"count": 1}
2025-09-22T10:00:00.001Z DEBUG checking SQL candidate {"index": 0, "candidate": "SELECT * FROM patients", "looks_like_sql": true}
2025-09-22T10:00:00.002Z DEBUG checking for bulk operation {"query": "SELECT * FROM patients"}
2025-09-22T10:00:00.002Z DEBUG checking SELECT for full table read {"has_where": false}
2025-09-22T10:00:00.002Z DEBUG detected full table SELECT
2025-09-22T10:00:00.003Z DEBUG successfully parsed event {"event_id": "abc-123", "query_type": "SELECT", "db_user": "alice"}
```

### Recommended Usage

1. For normal operation:
   ```yaml
   level: "info"
   console_level: "info"
   run_log: "./logs/run_log.jsonl"
   ```

2. For troubleshooting:
   ```yaml
   level: "debug"
   console_level: "info"  # Keep console clean
   debug_file: "./logs/debug.jsonl"
   info_file: "./logs/info.jsonl"
   development: true
   ```

## CLI Commands

AuditR provides several subcommands for different phases of audit log processing:

```bash
auditr [command] --help

Available Commands:
  parse       Convert raw DB audit logs → NDJSON events
  enrich      Enrich parsed audit events with sensitivity classification and risk scoring
  verify      Compute/validate hash chain, generate/verify checkpoints
  dict        Validate sensitivity dictionaries and risk scoring configs
  version     Show AuditR version
```

### 1. Parse Command

Convert raw audit logs into structured NDJSON format:

```bash
# Parse PostgreSQL pgAudit logs
auditr parse --db postgres --input pgaudit.log --output parsed.ndjson --emit-raw

# Parse MySQL Percona Audit logs
auditr parse --db mysql --input mysql_audit.log --output parsed.ndjson --emit-raw --reject-file rejected.jsonl

# Parse with streaming (tail mode)
auditr parse --db postgres --input pgaudit.log --follow --emit-raw
```

**Input**: Raw audit log files from pgAudit or Percona Audit Plugin  
**Output**: NDJSON with structured events including bulk operation detection:

**Bulk Operation Detection**: The parse step automatically detects and flags bulk operations:
- `bulk`: `true`/`false` - whether the operation is a bulk data operation
- `bulk_type`: `"insert"`/`"export"`/`"import"` - type of bulk operation
- `full_table_read`: `true`/`false` - whether the operation reads entire tables

**Bulk Detection Logic**:
- **Multi-row INSERT**: `INSERT ... VALUES (1,2), (3,4), (5,6)` or multiple VALUES clauses
- **Data Export**: `SELECT * FROM table` or `SELECT column1, column2 FROM table` (without WHERE)
- **Bulk Commands**: `COPY TO/FROM`, `LOAD DATA INFILE`, `SELECT INTO OUTFILE`
- **NOT Bulk**: `SELECT COUNT(*)`, `SELECT NOW()`, `SELECT 1`, system/metadata queries

```json
{
  "event_id": "abc-123-def",
  "timestamp": "2025-01-01T12:00:00Z",
  "db_system": "postgres",
  "db_user": "appuser1",
  "query_type": "SELECT",
  "raw_query": "SELECT ssn, email FROM healthcare.patient WHERE patient_id = '123';",
  "bulk": false
}
```

### 2. Enrich Command

Add sensitivity classification and risk scoring:

```bash
# Basic enrichment
auditr enrich \
  --schema postgres_schema.csv \
  --dict sensitivity_dict_extended.json \
  --risk risk_scoring.json \
  --input parsed.ndjson \
  --output enriched.ndjson \

# With debug information and unknown event emission
auditr enrich \
  --schema postgres_schema.csv \
  --dict sensitivity_dict_extended.json \
  --risk risk_scoring.json \
  --input parsed.ndjson \
  --output enriched.ndjson \
  --emit-unknown \
  --debug
```

**Input**: NDJSON from parse command + schema CSV + sensitivity dictionary + risk scoring policy  
**Output**: Enriched NDJSON with sensitivity and risk information (bulk fields are preserved from parse step):

```json
{
  "event_id": "abc-123-def",
  "timestamp": "2025-01-01T12:00:00Z",
  "db_system": "postgres",
  "db_user": "appuser1",
  "query_type": "SELECT",
  "raw_query": "SELECT ssn, email FROM healthcare.patient WHERE patient_id = '123';",
  "sensitivity": ["PII:ssn", "PII:email"],
  "risk_level": "medium",
  "bulk": false
}
```

### 3. Verify Command

Compute or validate per-event hash chains and manage checkpoints.

**Note**: The `--input` argument is required. Running `auditr verify` without arguments will show an error.

```bash
# Hash mode – writes hash fields, auto-checkpoint at file end if configured
auditr verify \
  --input enriched.ndjson \
  --output hashed.ndjson \
  --checkpoint            # optional (overrides config to force checkpoint)
  --private-key private.pem

# Hash mode without checkpointing (no private key needed)
auditr verify \
  --input enriched.ndjson \
  --output hashed.ndjson

# Verify mode – validate hash chain integrity only (no checkpoint verification)
auditr verify \
  --input hashed.ndjson \
  --summary              # print one-line result

# Verify mode with checkpoint validation – validate hash chain + checkpoint signature
auditr verify \
  --input hashed.ndjson \
  --checkpoint-path ./checkpoints/checkpoint-<ts>-<idx>.json \
  --public-key public.pem \
  --detailed
```

**Mode Selection:**
- **Hash mode**: When `--output` is provided (writes hashed file)
- **Verify mode**: When no `--output` is provided (reads and verifies existing hashed file)

**Key Requirements:**
- **Private key**: Only needed for hash mode when creating checkpoints (`--checkpoint` or `hashing.checkpoint_interval: file_end`)
- **Public key**: Only needed for verify mode when validating checkpoints (`--checkpoint-path` provided)

Notes:
- Summary/detailed:
  - `--summary` prints a single line and writes a slim run_log entry.
  - `--detailed` prints richer info and adds `duration_ms` to the run_log.
- Auto-checkpointing: if `hashing.checkpoint_interval: file_end` in config, a checkpoint is written at the end of each hash run without needing `--checkpoint`.
- Multi-file continuity: the chain continues across runs using `hashing.state_file`. Verifying files independently may flag the first event of a later file unless you verify the concatenated stream or reset state.

### 4. Schema CSV Format

The `--schema` flag expects a CSV file with the following format:

```csv
db_name,schema_name,table_name,column_name,column_type
practicumdb,healthcare,patient,patient_id,uuid
practicumdb,healthcare,patient,ssn,varchar
practicumdb,healthcare,patient,email,varchar
practicumdb,healthcare,patient,dob,date
practicumdb,healthcare,encounter,diagnosis,text
```

**Generate schema CSV:**
```bash
# PostgreSQL
psql -d practicumdb -c "
SELECT 
  current_database() as db_name,
  schemaname as schema_name,
  tablename as table_name,
  attname as column_name,
  format_type(atttypid, atttypmod) as column_type
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
JOIN pg_tables t ON c.relname = t.tablename AND n.nspname = t.schemaname
WHERE a.attnum > 0 AND NOT a.attisdropped
ORDER BY schemaname, tablename, attname;
" --csv > postgres_schema.csv

# MySQL
mysql -u user -p -D practicumdb -e "
SELECT 
  TABLE_SCHEMA as db_name,
  'default' as schema_name,
  TABLE_NAME as table_name,
  COLUMN_NAME as column_name,
  COLUMN_TYPE as column_type
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_SCHEMA = 'practicumdb'
ORDER BY TABLE_NAME, COLUMN_NAME;
" --batch --raw > mysql_schema.csv
```

## 📑 Sensitivity Dictionaries

AuditR uses JSON dictionaries to detect sensitive fields with regex-based matching:

### Dictionary Structure

```json
{
  "PII": [
    {
      "regex": "(?i)^ssn$",
      "expected_types": ["VARCHAR", "CHAR", "TEXT"],
      "sample_pattern": "^\\d{3}-\\d{2}-\\d{4}$"
    },
    {
      "regex": "(?i)^email$",
      "expected_types": ["VARCHAR", "TEXT"],
      "sample_pattern": ".+@.+\\..+"
    }
  ],
  "PHI": [
    {
      "regex": "(?i)diagnosis",
      "expected_types": ["VARCHAR", "TEXT"],
      "sample_pattern": ".*"
    }
  ],
  "Financial": [
    {
      "regex": "(?i)card.*last",
      "expected_types": ["VARCHAR", "CHAR"],
      "sample_pattern": "^\\d{4}$"
    }
  ],
  "negative": [
    {
      "regex": "(?i).*_id$",
      "reason": "ID fields are not sensitive data"
    }
  ]
}
```

### Risk Scoring Policy

```json
{
  "base": {
    "PII": "medium",
    "PHI": "high", 
    "Financial": "high"
  },
  "combinations": {
    "PII+PHI": "high",
    "PII+Financial": "critical",
    "PHI+Financial": "critical",
    "PII+PHI+Financial": "critical"
  },
  "default": "low"
}
```

### Features

* **Regex-based matching** for flexible column name detection
* **Type validation** ensures matches are on appropriate data types
* **Sample patterns** for additional validation (optional)
* **Negative rules** prevent false positives on ID fields, etc.
* **Risk combinations** handle multiple sensitivity categories

### Dictionary Validation

Validate your sensitivity dictionaries and risk scoring policies:

```bash
# Validate dictionary and risk scoring files
auditr dict validate \
  --dict sensitivity_dict_extended.json \
  --risk risk_scoring.json

# Example output:
# ✅ Dictionary validation passed: 3 categories, 11 rules, 2 negative rules
# ✅ Risk scoring validation passed: 3 base categories, 4 combinations
```

## Error Handling

AuditR follows a **never-lose-data** philosophy. When errors occur during processing, structured ERROR events are emitted instead of dropping data:

```json
{
  "event_id": "error-1759337683666707000",
  "timestamp": "2025-10-01T16:54:43Z",
  "query_type": "ERROR",
  "raw_query": "invalid json line",
  "error": {
    "phase": "enrich",
    "message": "JSON parse error: invalid character 'i' looking for beginning of value"
  }
}
```

## Run Log and Metrics

AuditR generates structured run logs in NDJSON format for monitoring and compliance:

```json
{
  "stage": "enrich",
  "ts": "2025-10-01T22:27:31+05:30",
  "counters": {
    "input_events": 100,
    "enriched_events": 25,
    "unknown_events": 70,
    "dropped_events": 0,
    "error_events": 5
  }
}
```

# 🧩 End-to-End Demo Pipeline

Here's a complete walkthrough of using LoadR and AuditR together:

## Step 1: Generate Schema + Data

```bash
# Build the tools
make

# Generate PostgreSQL seed data and import (see LoadR docs for details)
./bin/loadr load --config cmd/loadr/config/load_pg.yaml
createdb -U postgres practicumdb
psql -U postgres -d practicumdb -f seed_pg.sql
```

**📖 For detailed LoadR setup, see [LoadR Documentation](docs/loadr.md)**

## Step 2: Run Workload (Generate Audit Logs)

```bash
# Configure pgAudit in postgresql.conf:
# shared_preload_libraries = 'pgaudit'
# pgaudit.log = 'write, function, role, ddl'
# pgaudit.log_catalog = off

# Run synthetic workload
./bin/loadr run --config cmd/loadr/config/run_pg.yaml
```

## Step 3: Parse Audit Logs

```bash
# Parse pgAudit logs into structured NDJSON
./bin/auditr parse \
  --db postgres \
  --input /opt/homebrew/var/log/postgresql@16.log \
  --output parsed_events.ndjson \
  --reject-file rejected.jsonl \
  --emit-raw

# Check results
echo "Parsed $(wc -l < parsed_events.ndjson) events"
echo "Rejected $(wc -l < rejected.jsonl) lines"
```

## Step 4: Generate Schema CSV

```bash
# Extract schema information
psql -d practicumdb -c "
SELECT 
  current_database() as db_name,
  schemaname as schema_name,
  tablename as table_name,
  attname as column_name,
  format_type(atttypid, atttypmod) as column_type
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
JOIN pg_tables t ON c.relname = t.tablename AND n.nspname = t.schemaname
WHERE a.attnum > 0 AND NOT a.attisdropped
  AND schemaname IN ('healthcare', 'pharmacy', 'payments')
ORDER BY schemaname, tablename, attname;
" --csv > postgres_schema.csv
```

## Step 5: Enrich with Sensitivity Classification

```bash
# Enrich events with PII/PHI/Financial detection
./bin/auditr enrich \
  --schema postgres_schema.csv \
  --dict cmd/auditr/config/sensitivity_dict_extended.json \
  --risk cmd/auditr/config/risk_scoring.json \
  --input parsed_events.ndjson \
  --output enriched_events.ndjson \
  --emit-unknown \
  --debug

# Check enrichment results
echo "Enriched $(wc -l < enriched_events.ndjson) events"
```

## Step 6: Analyze Results

```bash
# Count sensitive events by category
jq -r 'select(.sensitivity and (.sensitivity | length > 0)) | .sensitivity[]' enriched_events.ndjson | \
  cut -d: -f1 | sort | uniq -c

# Count by risk level
jq -r '.risk_level' enriched_events.ndjson | sort | uniq -c

# Find high-risk events
jq 'select(.risk_level == "high" or .risk_level == "critical")' enriched_events.ndjson

# Find bulk operations
jq 'select(.bulk == true)' enriched_events.ndjson

# Check run log for metrics
cat logs/run_log.jsonl | jq .
```

## Expected Results

After running the complete pipeline, you should see:

- **Parsed Events**: ~200-500 structured audit events
- **Sensitive Data Detection**: PII (SSN, email, phone), PHI (diagnosis, treatment), Financial (payment info)
- **Risk Scoring**: Events classified as low/medium/high/critical based on data combinations
- **Bulk Operations**: SELECT * queries flagged as bulk operations
- **Error Handling**: Any malformed log lines converted to ERROR events
- **Run Metrics**: Detailed statistics in `logs/run_log.jsonl`

### Sample Enriched Event

```json
{
  "event_id": "abc-123-def",
  "timestamp": "2025-01-01T12:00:00Z",
  "db_system": "postgres",
  "db_user": "appuser1",
  "query_type": "INSERT",
  "raw_query": "INSERT INTO healthcare.patient (ssn, email, dob) VALUES ('123-45-6789', 'john@example.com', '1990-01-01');",
  "sensitivity": ["PII:ssn", "PII:email", "PII:dob"],
  "risk_level": "medium",
  "bulk": false,
  "debug_info": {
    "parsed_tables": {"patient": "patient"},
    "parsed_columns": ["ssn", "email", "dob"],
    "resolved_columns": 3,
    "matched_columns": 3,
    "schema_status": "matched"
  }
}
```

**Note**: The `bulk`, `bulk_type`, and `full_table_read` fields are populated during the parse step and preserved through enrichment.

# 📊 Visualization

The enriched NDJSON output can be easily analyzed and visualized using standard tools:

## Analysis Examples

```bash
# Top 10 most accessed sensitive columns
jq -r '.sensitivity[]?' enriched_events.ndjson | sort | uniq -c | sort -nr | head -10

# Risk level distribution
jq -r '.risk_level' enriched_events.ndjson | sort | uniq -c

# Users accessing sensitive data
jq -r 'select(.sensitivity and (.sensitivity | length > 0)) | .db_user' enriched_events.ndjson | sort | uniq -c

# Bulk operations by type
jq -r 'select(.bulk == true) | .bulk_type' enriched_events.ndjson | sort | uniq -c

# Timeline of high-risk events
jq -r 'select(.risk_level == "high" or .risk_level == "critical") | [.timestamp, .db_user, .risk_level, (.sensitivity | join(","))] | @csv' enriched_events.ndjson
```

## Integration with Analytics Tools

The NDJSON format is compatible with:

- **Elasticsearch/Kibana**: For real-time dashboards and alerting
- **Splunk**: For enterprise log analysis and compliance reporting  
- **Grafana**: For time-series visualization of audit metrics
- **Jupyter Notebooks**: For data science analysis and ML-based anomaly detection
- **Apache Spark**: For large-scale batch processing and analytics

# 📝 Crypto

## Key Management

The verify phase uses ECDSA P-256 for checkpoint signing and verification. When checkpointing is enabled, you must provide a private key for signing. When verifying checkpoints, you need both the public key and the checkpoint file.

### Generating Key Pairs

Generate a new ECDSA P-256 key pair for checkpoint signing:

```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out private.pem

# Extract public key from private key
openssl ec -in private.pem -pubout -out public.pem

# Verify the key pair
openssl ec -in private.pem -text -noout
openssl ec -in public.pem -pubin -text -noout
```

### Key Requirements

- **Private Key**: Required when creating checkpoints (hash mode with `--checkpoint` or `hashing.checkpoint_interval: file_end`)
- **Public Key**: Required when verifying checkpoints (verify mode with `--checkpoint-path`)
- **Format**: PEM-encoded ECDSA P-256 keys
- **Algorithm**: ECDSA P-256 (fixed, no algorithm selection)

### Example Usage

```bash
# Hash mode without checkpointing (no keys needed)
auditr verify --input enriched.ndjson --output hashed.ndjson

# Hash mode with checkpointing (requires private key)
auditr verify --input enriched.ndjson --output hashed.ndjson --checkpoint --private-key private.pem

# Verify mode without checkpoint validation (no keys needed)
auditr verify --input hashed.ndjson --summary

# Verify mode with checkpoint validation (requires public key + checkpoint file)
auditr verify --input hashed.ndjson --checkpoint-path ./checkpoints/checkpoint-*.json --public-key public.pem
```

# 📝 Future Enhancements

## Planned Features

- **Hash Chain Verification**: Tamper-evident audit trails with SHA-256 chaining
- **Query Command**: Filter and export enriched events for compliance reporting
- **Real-time Processing**: Stream processing mode for live audit log analysis
- **Advanced Analytics**: ML-based anomaly detection for unusual access patterns
- **Compliance Reports**: Pre-built templates for HIPAA, SOX, GDPR reporting
- **Web Dashboard**: Real-time visualization of audit metrics and alerts

## Extensibility

- **Custom Dictionaries**: Support for industry-specific sensitivity patterns
- **Plugin Architecture**: Custom enrichment processors and output formats
- **Database Connectors**: Direct integration with audit log tables
- **Alert Integration**: Webhook/email notifications for high-risk events
- **Multi-tenant Support**: Isolated processing for different organizations

# License
MIT License – free to use for academic or demo purposes.

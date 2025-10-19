package enrich

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// SchemaMap represents the nested schema structure: [schema_name][table_name][column_name] = normalized_type
type SchemaMap map[string]map[string]map[string]string

// LoadSchemaCSV loads a database schema from CSV format and returns a nested map structure.
// CSV format expected: db_name,schema_name,table_name,column_name,column_type
//
// The returned map structure is: [schema_name][table_name][column_name] = normalized_type
// Types are normalized by:
// - Converting to uppercase
// - Stripping size specifications (e.g., VARCHAR(255) -> VARCHAR)
// - Handling special cases for different databases
func LoadSchemaCSV(path string) (SchemaMap, error) {
	logger.L().Debugw("Loading schema from CSV", "path", path)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open schema file %s: %w", path, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Handle CSV files that might have quoted fields with commas (like enum types)
	reader.LazyQuotes = true
	// Allow variable number of fields to handle malformed rows gracefully
	reader.FieldsPerRecord = -1

	// Read header row
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Validate expected header format
	expectedHeader := []string{"db_name", "schema_name", "table_name", "column_name", "column_type"}
	if len(header) != len(expectedHeader) {
		return nil, fmt.Errorf("invalid CSV header: expected %v, got %v", expectedHeader, header)
	}

	for i, col := range header {
		if col != expectedHeader[i] {
			return nil, fmt.Errorf("invalid CSV header at position %d: expected %s, got %s", i, expectedHeader[i], col)
		}
	}

	schema := make(SchemaMap)
	rowCount := 0

	// Process each row
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV row %d: %w", rowCount+2, err) // +2 for header and 1-based indexing
		}

		if len(record) < 5 {
			logger.L().Warnw("Skipping malformed CSV row - insufficient fields",
				"row", rowCount+2,
				"columns", len(record),
				"record", strings.Join(record, ","))
			continue
		}

		dbName := strings.TrimSpace(record[0])
		schemaName := strings.TrimSpace(record[1])
		tableName := strings.TrimSpace(record[2])
		columnName := strings.TrimSpace(record[3])

		// Handle cases where column type might be split across multiple fields (e.g., enum with commas)
		var columnType string
		if len(record) == 5 {
			columnType = strings.TrimSpace(record[4])
		} else {
			// Rejoin the remaining fields as they likely belong to the column type
			columnTypeParts := make([]string, len(record)-4)
			for i := 4; i < len(record); i++ {
				columnTypeParts[i-4] = record[i]
			}
			columnType = strings.TrimSpace(strings.Join(columnTypeParts, ","))
			logger.L().Debugw("Rejoined column type from multiple fields",
				"column", columnName,
				"rejoined_type", columnType,
				"original_parts", strings.Join(columnTypeParts, ","))
		}

		// Skip empty rows
		if dbName == "" || schemaName == "" || tableName == "" || columnName == "" || columnType == "" {
			logger.L().Warnw("Skipping row with empty fields",
				"row", rowCount+2,
				"record", strings.Join(record, ","))
			continue
		}

		// Normalize the column type
		normalizedType := normalizeColumnType(columnType)

		// Initialize nested maps if they don't exist
		if schema[schemaName] == nil {
			schema[schemaName] = make(map[string]map[string]string)
		}
		if schema[schemaName][tableName] == nil {
			schema[schemaName][tableName] = make(map[string]string)
		}

		// Store the column with normalized type
		schema[schemaName][tableName][columnName] = normalizedType
		rowCount++

		logger.L().Debugw("Loaded schema column",
			"db", dbName,
			"schema", schemaName,
			"table", tableName,
			"column", columnName,
			"original_type", columnType,
			"normalized_type", normalizedType)
	}

	logger.L().Debugw("Schema loading completed",
		"total_columns", rowCount,
		"schemas", len(schema))

	// Log summary of loaded schemas and tables
	for schemaName, tables := range schema {
		tableCount := len(tables)
		columnCount := 0
		for _, columns := range tables {
			columnCount += len(columns)
		}
		logger.L().Debugw("Schema summary",
			"schema", schemaName,
			"tables", tableCount,
			"columns", columnCount)
	}

	return schema, nil
}

// normalizeColumnType normalizes database column types for consistent matching.
// This handles differences between MySQL and PostgreSQL type representations.
func normalizeColumnType(columnType string) string {
	// Convert to uppercase for consistency
	normalized := strings.ToUpper(strings.TrimSpace(columnType))

	// Remove size specifications using regex
	// Matches patterns like VARCHAR(255), CHAR(36), DECIMAL(12,2), etc.
	sizePattern := regexp.MustCompile(`\([^)]*\)`)
	normalized = sizePattern.ReplaceAllString(normalized, "")

	// Handle special type mappings and aliases
	switch normalized {
	case "CHARACTER VARYING":
		return "VARCHAR"
	case "CHARACTER":
		return "CHAR"
	case "TIMESTAMP WITH TIME ZONE":
		return "TIMESTAMPTZ"
	case "TIMESTAMP WITHOUT TIME ZONE":
		return "TIMESTAMP"
	case "DOUBLE PRECISION":
		return "DOUBLE"
	case "BIGINT":
		return "BIGINT"
	case "SMALLINT":
		return "SMALLINT"
	case "TINYINT":
		return "TINYINT"
	case "USER-DEFINED":
		// PostgreSQL user-defined types (like custom domains)
		return "TEXT" // Treat as TEXT for sensitivity matching
	case "ENUM":
		return "VARCHAR" // Treat enums as VARCHAR for sensitivity matching
	}

	// Handle integer types - keep them distinct for better sensitivity matching
	switch normalized {
	case "INTEGER":
		return "INT"
	case "TINYINT":
		return "TINYINT"
	case "SMALLINT":
		return "SMALLINT"
	case "BIGINT":
		return "BIGINT"
	}

	return normalized
}

// GetColumnType retrieves the normalized type for a specific column.
// Returns empty string if the column is not found in the schema.
func (sm SchemaMap) GetColumnType(schemaName, tableName, columnName string) string {
	if schema, exists := sm[schemaName]; exists {
		if table, exists := schema[tableName]; exists {
			if colType, exists := table[columnName]; exists {
				return colType
			}
		}
	}
	return ""
}

// HasColumn checks if a column exists in the schema.
func (sm SchemaMap) HasColumn(schemaName, tableName, columnName string) bool {
	return sm.GetColumnType(schemaName, tableName, columnName) != ""
}

// GetTableColumns returns all columns for a given table.
// Returns nil if the table is not found.
func (sm SchemaMap) GetTableColumns(schemaName, tableName string) map[string]string {
	if schema, exists := sm[schemaName]; exists {
		if table, exists := schema[tableName]; exists {
			// Return a copy to prevent external modification
			result := make(map[string]string)
			for col, typ := range table {
				result[col] = typ
			}
			return result
		}
	}
	return nil
}

// GetSchemaNames returns all schema names in the loaded schema.
func (sm SchemaMap) GetSchemaNames() []string {
	var names []string
	for schemaName := range sm {
		names = append(names, schemaName)
	}
	return names
}

// GetTableNames returns all table names in a given schema.
func (sm SchemaMap) GetTableNames(schemaName string) []string {
	var names []string
	if schema, exists := sm[schemaName]; exists {
		for tableName := range schema {
			names = append(names, tableName)
		}
	}
	return names
}

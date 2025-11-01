package enrich

import (
	"regexp"
	"strings"

	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// QueryRefs represents the tables and columns referenced in a SQL query
type QueryRefs struct {
	// Tables maps table names/aliases to their actual table names
	// Key: alias or table name used in query, Value: actual table name
	Tables map[string]string

	// Columns contains all column references found in the query
	// Format: "table.column" or just "column" if no table prefix
	Columns []string

	// IsBulk indicates if this appears to be a bulk operation
	IsBulk bool

	// BulkType describes the type of bulk operation (if IsBulk is true)
	BulkType string // "import", "export", "insert", "select"
}

// ParseQuery extracts table and column references from a SQL query using simple regex heuristics.
// This is intentionally kept simple and may not handle all edge cases - it's designed for
// common audit log patterns rather than full SQL parsing.
//
// Supported patterns:
// - SELECT columns FROM table
// - SELECT table.column, alias.column FROM table alias
// - INSERT INTO table (columns)
// - UPDATE table SET column = value
// - DELETE FROM table
// - Basic JOINs
// - Simple subqueries (limited)

// cleanSQLComments removes SQL comments from a query to prevent them from interfering with parsing.
// Handles both /* block comments */ and -- line comments
func cleanSQLComments(query string) string {
	// Remove /* block comments */
	blockCommentRegex := regexp.MustCompile(`/\*.*?\*/`)
	cleaned := blockCommentRegex.ReplaceAllString(query, " ")

	// Remove -- line comments (from -- to end of line)
	lineCommentRegex := regexp.MustCompile(`--.*?(?:\n|$)`)
	cleaned = lineCommentRegex.ReplaceAllString(cleaned, " ")

	// Clean up extra whitespace
	spaceRegex := regexp.MustCompile(`\s+`)
	cleaned = spaceRegex.ReplaceAllString(cleaned, " ")

	return strings.TrimSpace(cleaned)
}

func ParseQuery(rawQuery string) QueryRefs {
	logger.L().Debugw("Parsing SQL query", "query", rawQuery)

	refs := QueryRefs{
		Tables:  make(map[string]string),
		Columns: []string{},
	}

	// Normalize the query: remove extra whitespace, convert to uppercase for pattern matching
	query := strings.TrimSpace(rawQuery)
	if query == "" {
		return refs
	}

	// Clean SQL comments before parsing to avoid extracting comment content as columns
	cleanQuery := cleanSQLComments(query)

	// Check for bulk operations first
	refs.IsBulk, refs.BulkType = detectBulkOperation(cleanQuery)

	// Extract table references and aliases
	extractTables(cleanQuery, &refs)

	// Extract column references
	extractColumns(cleanQuery, &refs)

	logger.L().Debugw("Query parsing completed",
		"tables", refs.Tables,
		"columns", strings.Join(refs.Columns, ","),
		"is_bulk", refs.IsBulk,
		"bulk_type", refs.BulkType)

	return refs
}

// detectBulkOperation checks if the query represents a bulk operation
func detectBulkOperation(query string) (bool, string) {
	queryUpper := strings.ToUpper(query)

	// PostgreSQL bulk operations
	if strings.Contains(queryUpper, "COPY ") {
		if strings.Contains(queryUpper, " TO ") {
			return true, "export"
		}
		if strings.Contains(queryUpper, " FROM ") {
			return true, "import"
		}
		return true, "copy"
	}

	// MySQL bulk operations
	if strings.Contains(queryUpper, "LOAD DATA") {
		return true, "import"
	}
	if strings.Contains(queryUpper, "SELECT ") && strings.Contains(queryUpper, " INTO OUTFILE") {
		return true, "export"
	}

	// Multi-row INSERT (simple heuristic: multiple VALUES clauses)
	if strings.Contains(queryUpper, "INSERT ") {
		valueCount := strings.Count(queryUpper, "VALUES")
		if valueCount > 1 || strings.Contains(queryUpper, "INSERT ") && strings.Contains(queryUpper, " SELECT ") {
			return true, "insert"
		}
	}

	// SELECT * without WHERE (potential full table scan)
	if strings.Contains(queryUpper, "SELECT *") && !strings.Contains(queryUpper, " WHERE ") {
		return true, "select"
	}

	return false, ""
}

// extractTables finds table references and aliases in the query
func extractTables(query string, refs *QueryRefs) {
	queryUpper := strings.ToUpper(query)

	// Pattern 1: FROM schema.table_name alias (with alias) - supports schema-qualified names
	fromWithAliasPattern := regexp.MustCompile(`(?i)\bFROM\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	fromAliasMatches := fromWithAliasPattern.FindAllStringSubmatch(query, -1)
	validAliasFound := false

	for _, match := range fromAliasMatches {
		fullTableName := match[1]
		alias := match[2]

		if !isReservedWord(alias) {
			// Extract just the table name (last part after dot)
			tableName := fullTableName
			if strings.Contains(fullTableName, ".") {
				parts := strings.Split(fullTableName, ".")
				tableName = parts[len(parts)-1]
			}
			// Table has an alias
			refs.Tables[alias] = tableName
			refs.Tables[tableName] = tableName // Also map table name to itself
			validAliasFound = true
			logger.L().Debugw("Found FROM table with alias",
				"full_table", fullTableName,
				"table", tableName,
				"alias", alias)
		}
	}

	// Pattern 1b: FROM table_name (without alias, only if no valid alias was found)
	if !validAliasFound {
		fromPattern := regexp.MustCompile(`(?i)\bFROM\s+([a-zA-Z_][a-zA-Z0-9_.]*)\b`)
		fromMatches := fromPattern.FindAllStringSubmatch(query, -1)
		for _, match := range fromMatches {
			fullTableName := match[1]
			// Extract just the table name (last part after dot)
			tableName := fullTableName
			if strings.Contains(fullTableName, ".") {
				parts := strings.Split(fullTableName, ".")
				tableName = parts[len(parts)-1]
			}
			refs.Tables[tableName] = tableName
			logger.L().Debugw("Found FROM table without alias",
				"full_table", fullTableName,
				"table", tableName)
		}
	}

	// Pattern 2: JOIN schema.table_name alias (with alias) - supports schema-qualified names
	joinWithAliasPattern := regexp.MustCompile(`(?i)\b(?:INNER\s+|LEFT\s+|RIGHT\s+|FULL\s+)?JOIN\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	joinAliasMatches := joinWithAliasPattern.FindAllStringSubmatch(query, -1)
	joinTablesFound := make(map[string]bool)

	for _, match := range joinAliasMatches {
		fullTableName := match[1]
		alias := match[2]

		if !isReservedWord(alias) {
			// Extract just the table name (last part after dot)
			tableName := fullTableName
			if strings.Contains(fullTableName, ".") {
				parts := strings.Split(fullTableName, ".")
				tableName = parts[len(parts)-1]
			}
			refs.Tables[alias] = tableName
			refs.Tables[tableName] = tableName
			joinTablesFound[tableName] = true
			logger.L().Debugw("Found JOIN table with alias",
				"full_table", fullTableName,
				"table", tableName,
				"alias", alias)
		}
	}

	// Pattern 2b: JOIN table_name (without alias)
	joinPattern := regexp.MustCompile(`(?i)\b(?:INNER\s+|LEFT\s+|RIGHT\s+|FULL\s+)?JOIN\s+([a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	joinMatches := joinPattern.FindAllStringSubmatch(query, -1)
	for _, match := range joinMatches {
		fullTableName := match[1]
		// Extract just the table name (last part after dot)
		tableName := fullTableName
		if strings.Contains(fullTableName, ".") {
			parts := strings.Split(fullTableName, ".")
			tableName = parts[len(parts)-1]
		}
		// Only add if we didn't already find this table with an alias
		if !joinTablesFound[tableName] {
			refs.Tables[tableName] = tableName
			logger.L().Debugw("Found JOIN table without alias",
				"full_table", fullTableName,
				"table", tableName)
		}
	}

	// Pattern 3: INSERT INTO table_name - support schema-qualified table names
	if strings.Contains(queryUpper, "INSERT INTO") {
		insertPattern := regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_.]*)\b`)
		insertMatches := insertPattern.FindStringSubmatch(query)
		if len(insertMatches) > 1 {
			fullTableName := insertMatches[1]
			// Extract just the table name (last part after dot)
			tableName := fullTableName
			if strings.Contains(fullTableName, ".") {
				parts := strings.Split(fullTableName, ".")
				tableName = parts[len(parts)-1]
			}
			refs.Tables[tableName] = tableName
			logger.L().Debugw("Found INSERT table", "table", tableName, "full_name", fullTableName)
		}
	}

	// Pattern 4: UPDATE table_name [alias] - support schema-qualified table names
	if strings.Contains(queryUpper, "UPDATE") {
		// Try with alias first - alias must not be followed by SET
		updateWithAliasPattern := regexp.MustCompile(`(?i)\bUPDATE\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+SET\b`)
		updateAliasMatches := updateWithAliasPattern.FindStringSubmatch(query)

		if len(updateAliasMatches) > 2 {
			fullTableName := updateAliasMatches[1]
			alias := updateAliasMatches[2]

			if !isReservedWord(alias) {
				// Extract just the table name (last part after dot)
				tableName := fullTableName
				if strings.Contains(fullTableName, ".") {
					parts := strings.Split(fullTableName, ".")
					tableName = parts[len(parts)-1]
				}
				refs.Tables[alias] = tableName
				refs.Tables[tableName] = tableName
				logger.L().Debugw("Found UPDATE table with alias",
					"full_table", fullTableName,
					"table", tableName,
					"alias", alias)
			}
		} else {
			// Try without alias - table name followed by SET
			updatePattern := regexp.MustCompile(`(?i)\bUPDATE\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+SET\b`)
			updateMatches := updatePattern.FindStringSubmatch(query)
			if len(updateMatches) > 1 {
				fullTableName := updateMatches[1]
				// Extract just the table name (last part after dot)
				tableName := fullTableName
				if strings.Contains(fullTableName, ".") {
					parts := strings.Split(fullTableName, ".")
					tableName = parts[len(parts)-1]
				}
				refs.Tables[tableName] = tableName
				logger.L().Debugw("Found UPDATE table without alias",
					"full_table", fullTableName,
					"table", tableName)
			}
		}
	}

	// Pattern 5: DELETE FROM table_name - support schema-qualified table names
	if strings.Contains(queryUpper, "DELETE FROM") {
		deletePattern := regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_.]*)\b`)
		deleteMatches := deletePattern.FindStringSubmatch(query)
		if len(deleteMatches) > 1 {
			fullTableName := deleteMatches[1]
			// Extract just the table name (last part after dot)
			tableName := fullTableName
			if strings.Contains(fullTableName, ".") {
				parts := strings.Split(fullTableName, ".")
				tableName = parts[len(parts)-1]
			}
			refs.Tables[tableName] = tableName
			logger.L().Debugw("Found DELETE table",
				"full_table", fullTableName,
				"table", tableName)
		}
	}
}

// extractColumns finds column references in the query
func extractColumns(query string, refs *QueryRefs) {
	queryUpper := strings.ToUpper(query)

	// Handle SELECT * case
	if strings.Contains(queryUpper, "SELECT *") {
		refs.Columns = append(refs.Columns, "*")
		logger.L().Debug("Found SELECT * - wildcard column reference")
		return
	}

	// Pattern 1: SELECT column list
	if strings.Contains(queryUpper, "SELECT") {
		selectPattern := regexp.MustCompile(`(?i)\bSELECT\s+(.*?)\s+FROM\b`)
		selectMatches := selectPattern.FindStringSubmatch(query)
		if len(selectMatches) > 1 {
			columnList := selectMatches[1]
			extractColumnList(columnList, refs)
		}
	}

	// Pattern 2: INSERT INTO table (column_list) - support schema-qualified table names
	if strings.Contains(queryUpper, "INSERT INTO") {
		insertColPattern := regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+[a-zA-Z_][a-zA-Z0-9_.]*\s*\(\s*(.*?)\s*\)`)
		insertMatches := insertColPattern.FindStringSubmatch(query)
		if len(insertMatches) > 1 {
			columnList := insertMatches[1]
			extractColumnList(columnList, refs)
		}
	}

	// Pattern 3: UPDATE SET column = value
	if strings.Contains(queryUpper, "UPDATE") && strings.Contains(queryUpper, "SET") {
		setPattern := regexp.MustCompile(`(?i)\bSET\s+(.*?)(?:\s+WHERE|\s*$)`)
		setMatches := setPattern.FindStringSubmatch(query)
		if len(setMatches) > 1 {
			setClause := setMatches[1]
			// Extract column names from "col1 = val1, col2 = val2" format
			assignments := strings.Split(setClause, ",")
			for _, assignment := range assignments {
				parts := strings.Split(assignment, "=")
				if len(parts) >= 1 {
					columnName := strings.TrimSpace(parts[0])
					if columnName != "" {
						refs.Columns = append(refs.Columns, columnName)
						logger.L().Debugw("Found UPDATE column", "column", columnName)
					}
				}
			}
		}
	}

	// Pattern 4: WHERE clause columns (basic extraction)
	if strings.Contains(queryUpper, "WHERE") {
		wherePattern := regexp.MustCompile(`(?i)\bWHERE\s+(.*?)(?:\s+ORDER\s+BY|\s+GROUP\s+BY|\s+HAVING|\s+LIMIT|\s*$)`)
		whereMatches := wherePattern.FindStringSubmatch(query)
		if len(whereMatches) > 1 {
			whereClause := whereMatches[1]
			extractWhereColumns(whereClause, refs)
		}
	}
}

// extractColumnList parses a comma-separated list of columns
func extractColumnList(columnList string, refs *QueryRefs) {
	// Remove common SQL functions and focus on column names
	columns := strings.Split(columnList, ",")

	for _, col := range columns {
		col = strings.TrimSpace(col)
		if col == "" || col == "*" {
			continue
		}

		// Handle table.column format and aliases
		if strings.Contains(col, ".") {
			// Check if there's an alias (AS keyword or just space)
			parts := strings.Fields(col)
			if len(parts) > 0 {
				columnName := parts[0] // Take the first part (before AS or alias)
				refs.Columns = append(refs.Columns, columnName)
				logger.L().Debugw("Found qualified column", "column", columnName)
			}
		} else {
			// Simple column name (remove AS aliases)
			parts := strings.Fields(col)
			if len(parts) > 0 {
				columnName := parts[0]
				// Skip obvious functions, numbers, and reserved words
				if !strings.Contains(columnName, "(") && !isReservedWord(columnName) && !isNumeric(columnName) && isValidColumnName(columnName) {
					refs.Columns = append(refs.Columns, columnName)
					logger.L().Debugw("Found column", "column", columnName)
				}
			}
		}
	}
}

// extractWhereColumns extracts column references from WHERE clauses (basic implementation)
func extractWhereColumns(whereClause string, refs *QueryRefs) {
	// This is a simplified extraction - just look for table.column patterns
	columnPattern := regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)\b`)
	matches := columnPattern.FindAllStringSubmatch(whereClause, -1)

	for _, match := range matches {
		columnRef := match[1]
		// Skip if it looks like an assignment (contains =)
		if !strings.Contains(columnRef, "=") && !isReservedWord(columnRef) {
			refs.Columns = append(refs.Columns, columnRef)
			logger.L().Debugw("Found WHERE column", "column", columnRef)
		}
	}
}

// isReservedWord checks if a word is a common SQL reserved word that shouldn't be treated as a table/column name
func isReservedWord(word string) bool {
	reserved := map[string]bool{
		"SELECT": true, "FROM": true, "WHERE": true, "INSERT": true, "UPDATE": true, "DELETE": true,
		"JOIN": true, "INNER": true, "LEFT": true, "RIGHT": true, "FULL": true, "ON": true,
		"SET": true, "VALUES": true, "INTO": true, "AS": true, "AND": true, "OR": true,
		"ORDER": true, "BY": true, "GROUP": true, "HAVING": true, "LIMIT": true, "OFFSET": true,
		"UNION": true, "ALL": true, "DISTINCT": true, "COUNT": true, "SUM": true, "AVG": true,
		"MAX": true, "MIN": true, "NULL": true, "NOT": true, "IN": true, "EXISTS": true,
		"BETWEEN": true, "LIKE": true, "IS": true, "CASE": true, "WHEN": true, "THEN": true,
		"ELSE": true, "END": true,
	}
	return reserved[strings.ToUpper(word)]
}

// ResolveColumns resolves column references against a schema map and returns
// a map of resolved columns with their types.
// Uses smart schema resolution - searches all schemas automatically.
// Returns: map[qualified_column_name]normalized_type
func (qr *QueryRefs) ResolveColumns(schema SchemaMap) map[string]string {
	resolved := make(map[string]string)

	logger.L().Debugw("Resolving columns with smart schema resolution",
		"num_parsed_columns", len(qr.Columns),
		"parsed_tables", qr.Tables)

	for _, columnRef := range qr.Columns {
		if columnRef == "*" {
			// Wildcard - resolve all columns from all referenced tables
			for alias, tableName := range qr.Tables {
				tableColumns := qr.findTableInAnySchema(schema, tableName)
				if tableColumns != nil {
					for colName, colType := range tableColumns {
						qualifiedName := alias + "." + colName
						resolved[qualifiedName] = colType
						logger.L().Debugw("Resolved wildcard column",
							"table", tableName,
							"column", colName,
							"type", colType)
					}
				} else {
					logger.L().Warnw("Could not resolve wildcard table in any schema",
						"table", tableName)
				}
			}
			continue
		}

		if strings.Contains(columnRef, ".") {
			// Qualified column reference: table.column
			parts := strings.SplitN(columnRef, ".", 2)
			if len(parts) == 2 {
				tableAlias := parts[0]
				columnName := parts[1]

				// Resolve table alias to actual table name
				if actualTable, exists := qr.Tables[tableAlias]; exists {
					tableColumns := qr.findTableInAnySchema(schema, actualTable)
					if tableColumns != nil {
						if colType, exists := tableColumns[columnName]; exists {
							resolved[columnRef] = colType
							logger.L().Debugw("Resolved qualified column",
								"column", columnRef,
								"table", actualTable,
								"type", colType)
						} else {
							logger.L().Warnw("Column not found in table",
								"column", columnName,
								"table", actualTable)
						}
					} else {
						logger.L().Warnw("Could not resolve qualified table in any schema",
							"table", actualTable)
					}
				}
			}
		} else {
			// Unqualified column reference - try to resolve against all known tables
			columnName := columnRef
			found := false
			for alias, tableName := range qr.Tables {
				tableColumns := qr.findTableInAnySchema(schema, tableName)
				if tableColumns != nil {
					if colType, exists := tableColumns[columnName]; exists {
						qualifiedName := alias + "." + columnName
						resolved[qualifiedName] = colType
						found = true
						logger.L().Debugw("Resolved unqualified column",
							"column", columnName,
							"table", tableName,
							"type", colType)
						break // Stop after first match to avoid duplicates
					}
				}
			}
			if !found {
				logger.L().Warnw("Could not resolve unqualified column in any table",
					"column", columnName)
			}
		}
	}

	logger.L().Debugw("Column resolution completed",
		"input_columns", len(qr.Columns),
		"resolved_columns", len(resolved))

	return resolved
}

// findTableInAnySchema searches for a table across all schemas
// Returns the table's column map if found, nil otherwise
func (qr *QueryRefs) findTableInAnySchema(schema SchemaMap, tableName string) map[string]string {
	for schemaName, tables := range schema {
		if tableColumns, exists := tables[tableName]; exists {
			logger.L().Debugw("Found table in schema",
				"table", tableName,
				"schema", schemaName,
				"columns", len(tableColumns))
			return tableColumns
		}
	}
	return nil
}

// isNumeric checks if a string is a numeric literal.
func isNumeric(s string) bool {
	return regexp.MustCompile(`^\d+(\.\d+)?$`).MatchString(s)
}

// isValidColumnName checks if a string looks like a valid column name
func isValidColumnName(s string) bool {
	// Must start with letter or underscore, followed by letters, numbers, or underscores
	// Must not contain special characters like =, -, etc.
	validColumnPattern := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	return validColumnPattern.MatchString(s) && !strings.Contains(s, "=") && !strings.Contains(s, "-")
}

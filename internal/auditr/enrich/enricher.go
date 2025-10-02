package enrich

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// EnrichmentOptions contains configuration options for the enrichment process
type EnrichmentOptions struct {
	// EmitUnknown determines whether to emit events with no sensitivity matches
	EmitUnknown bool

	// Debug enables debug information in the output
	Debug bool
}

// Enricher handles the enrichment of audit events with sensitivity and risk information
type Enricher struct {
	schema      SchemaMap
	dict        *CompiledSensitivityDict
	riskScoring *config.RiskScoring
	options     EnrichmentOptions
}

// EnrichmentResult represents the result of enriching a single event
type EnrichmentResult struct {
	// EnrichedEvent contains the original event with added enrichment fields
	EnrichedEvent map[string]interface{}

	// ShouldEmit indicates whether this event should be included in the output
	ShouldEmit bool

	// Categories contains the sensitivity categories that were matched
	Categories []string

	// RiskLevel is the computed risk level for this event
	RiskLevel string

	// Error contains any error that occurred during enrichment
	Error error
}

// NewEnricher creates a new enricher with the provided components
func NewEnricher(schema SchemaMap, dict *CompiledSensitivityDict, riskScoring *config.RiskScoring, options EnrichmentOptions) *Enricher {
	logger.L().Infow("Creating new enricher",
		"schema_entries", len(schema),
		"dict_categories", len(dict.Categories),
		"emit_unknown", options.EmitUnknown,
		"debug", options.Debug)

	return &Enricher{
		schema:      schema,
		dict:        dict,
		riskScoring: riskScoring,
		options:     options,
	}
}

// ProcessEvent enriches a single audit event with sensitivity and risk information.
// The input event should be a parsed NDJSON event (map[string]interface{}).
// Returns an EnrichmentResult containing the enriched event and metadata.
func (e *Enricher) ProcessEvent(event map[string]interface{}) EnrichmentResult {
	// Extract required fields from the event
	eventID, _ := event["event_id"].(string)
	rawQuery, _ := event["raw_query"].(string)
	dbSystem, _ := event["db_system"].(string)

	logger.L().Debugw("Processing event for enrichment",
		"event_id", eventID,
		"db_system", dbSystem,
		"raw_query", rawQuery)

	// Create a copy of the original event to avoid modifying the input
	enrichedEvent := make(map[string]interface{})
	for k, v := range event {
		enrichedEvent[k] = v
	}

	// Step 1: Parse the SQL query to extract table and column references
	queryRefs := ParseQuery(rawQuery)

	logger.L().Debugw("Query parsing completed",
		"event_id", eventID,
		"tables", queryRefs.Tables,
		"columns", strings.Join(queryRefs.Columns, ","),
		"is_bulk", queryRefs.IsBulk,
		"bulk_type", queryRefs.BulkType)

	// Step 2: Resolve column references against the schema
	resolvedColumns := queryRefs.ResolveColumns(e.schema)

	logger.L().Debugw("Column resolution completed",
		"event_id", eventID,
		"resolved_columns", len(resolvedColumns))

	// Step 3: Match resolved columns against sensitivity dictionary
	categoryMatches := make(map[string][]string) // category -> list of matched columns
	allMatchedColumns := make([]string, 0)

	for qualifiedColumn, columnType := range resolvedColumns {
		// Extract just the column name for matching (remove table prefix)
		columnName := qualifiedColumn
		if strings.Contains(qualifiedColumn, ".") {
			parts := strings.SplitN(qualifiedColumn, ".", 2)
			if len(parts) == 2 {
				columnName = parts[1]
			}
		}

		// Find matches for this column
		matches := e.dict.FindMatches(columnName, columnType)

		for category, rules := range matches {
			if categoryMatches[category] == nil {
				categoryMatches[category] = make([]string, 0)
			}
			categoryMatches[category] = append(categoryMatches[category], qualifiedColumn)
			allMatchedColumns = append(allMatchedColumns, qualifiedColumn)

			logger.L().Debugw("Column matched sensitivity category",
				"event_id", eventID,
				"column", qualifiedColumn,
				"column_name", columnName,
				"column_type", columnType,
				"category", category,
				"matching_rules", len(rules))
		}
	}

	// Step 4: Extract categories and compute risk level
	categories := make([]string, 0, len(categoryMatches))
	for category := range categoryMatches {
		categories = append(categories, category)
	}

	riskLevel := ComputeRisk(e.riskScoring, categories)

	logger.L().Debugw("Risk computation completed",
		"event_id", eventID,
		"categories", strings.Join(categories, ","),
		"risk_level", riskLevel)

	// Step 5: Determine if event should be emitted
	shouldEmit := len(categories) > 0 || e.options.EmitUnknown

	// Step 6: Build enrichment fields
	if shouldEmit {
		// Add sensitivity information
		if len(categories) > 0 {
			// Build sensitivity array in the format "Category:column"
			sensitivityArray := make([]string, 0)
			for category, columns := range categoryMatches {
				for _, column := range columns {
					// Extract just the column name for the sensitivity label
					columnName := column
					if strings.Contains(column, ".") {
						parts := strings.SplitN(column, ".", 2)
						if len(parts) == 2 {
							columnName = parts[1]
						}
					}
					sensitivityArray = append(sensitivityArray, fmt.Sprintf("%s:%s", category, columnName))
				}
			}
			enrichedEvent["sensitivity"] = sensitivityArray
		} else {
			// No matches found, but emitting unknown
			enrichedEvent["sensitivity"] = []string{}
		}

		// Add risk level
		enrichedEvent["risk_level"] = riskLevel

		// Add bulk operation flag
		if queryRefs.IsBulk {
			enrichedEvent["bulk"] = true
			if queryRefs.BulkType != "" {
				enrichedEvent["bulk_type"] = queryRefs.BulkType
			}
		}

		// Add debug information if requested
		if e.options.Debug {
			debugInfo := map[string]interface{}{
				"parsed_tables":    queryRefs.Tables,
				"parsed_columns":   queryRefs.Columns,
				"resolved_columns": len(resolvedColumns),
				"matched_columns":  len(allMatchedColumns),
				"category_matches": categoryMatches,
			}

			// Add schema status
			if len(resolvedColumns) > 0 {
				debugInfo["schema_status"] = "matched"
			} else if len(queryRefs.Columns) > 0 {
				debugInfo["schema_status"] = "unresolved"
				// Add list of unresolved tables
				unresolvedTables := make([]string, 0)
				for _, tableName := range queryRefs.Tables {
					// Check if table exists in any schema
					tableFound := false
					for _, tables := range e.schema {
						if _, ok := tables[tableName]; ok {
							tableFound = true
							break
						}
					}
					if !tableFound {
						unresolvedTables = append(unresolvedTables, tableName)
					}
				}
				if len(unresolvedTables) > 0 {
					debugInfo["unresolved_tables"] = unresolvedTables
				}
			} else {
				debugInfo["schema_status"] = "no_columns"
			}

			enrichedEvent["debug_info"] = debugInfo
		}

		logger.L().Infow("Event enrichment completed",
			"event_id", eventID,
			"categories", strings.Join(categories, ","),
			"risk_level", riskLevel,
			"is_bulk", queryRefs.IsBulk,
			"sensitivity_matches", len(allMatchedColumns),
			"should_emit", shouldEmit)
	} else {
		logger.L().Debugw("Event dropped - no sensitivity matches and emit_unknown=false",
			"event_id", eventID)
	}

	return EnrichmentResult{
		EnrichedEvent: enrichedEvent,
		ShouldEmit:    shouldEmit,
		Categories:    categories,
		RiskLevel:     riskLevel,
		Error:         nil,
	}
}

// ProcessEventJSON is a convenience method that accepts and returns JSON strings
func (e *Enricher) ProcessEventJSON(eventJSON string) (string, bool, error) {
	// Parse input JSON
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return "", false, fmt.Errorf("failed to parse input JSON: %w", err)
	}

	// Process the event
	result := e.ProcessEvent(event)
	if result.Error != nil {
		return "", false, result.Error
	}

	// Return early if event should not be emitted
	if !result.ShouldEmit {
		return "", false, nil
	}

	// Marshal enriched event back to JSON
	enrichedJSON, err := json.Marshal(result.EnrichedEvent)
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal enriched event: %w", err)
	}

	return string(enrichedJSON), true, nil
}

// GetStats returns statistics about the enricher configuration
func (e *Enricher) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"schema_schemas":      len(e.schema),
		"dict_categories":     len(e.dict.Categories),
		"dict_negative_rules": len(e.dict.Negative),
		"risk_base_rules":     len(e.riskScoring.Base),
		"risk_combinations":   len(e.riskScoring.Combinations),
		"emit_unknown":        e.options.EmitUnknown,
		"debug_enabled":       e.options.Debug,
	}

	// Count total positive rules
	totalRules := 0
	for _, rules := range e.dict.Categories {
		totalRules += len(rules)
	}
	stats["dict_total_rules"] = totalRules

	// Count schema tables and columns
	totalTables := 0
	totalColumns := 0
	for _, tables := range e.schema {
		totalTables += len(tables)
		for _, columns := range tables {
			totalColumns += len(columns)
		}
	}
	stats["schema_tables"] = totalTables
	stats["schema_columns"] = totalColumns

	return stats
}

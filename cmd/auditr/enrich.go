package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/enrich"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich parsed audit events with sensitivity classification and risk scoring",
	Long: `Enrich takes parsed audit events (NDJSON format) and augments them with:
- Sensitivity classification (PII, PHI, Financial data detection)
- Risk scoring based on data categories and combinations
- Bulk operation detection and flagging

The enrichment process uses:
- Database schema (CSV format) to resolve column types
- Sensitivity dictionary (JSON) with regex patterns for data classification
- Risk scoring policy (JSON) for computing risk levels

Input: NDJSON stream of parsed audit events
Output: NDJSON stream of enriched events with sensitivity and risk information`,
	RunE: runEnrich,
}

var (
	enrichFlagSchema      string
	enrichFlagDict        string
	enrichFlagRisk        string
	enrichFlagInput       string
	enrichFlagOutput      string
	enrichFlagEmitUnknown bool
	enrichFlagDebug       bool
)

func init() {
	enrichCmd.Flags().StringVar(&enrichFlagSchema, "schema", "", "database schema CSV file (required)")
	enrichCmd.Flags().StringVar(&enrichFlagDict, "dict", "", "sensitivity dictionary JSON file (required)")
	enrichCmd.Flags().StringVar(&enrichFlagRisk, "risk", "", "risk scoring policy JSON file (required)")
	enrichCmd.Flags().StringVar(&enrichFlagInput, "input", "", "input NDJSON file (default stdin)")
	enrichCmd.Flags().StringVar(&enrichFlagOutput, "output", "", "output NDJSON file (default stdout)")
	enrichCmd.Flags().BoolVar(&enrichFlagEmitUnknown, "emit-unknown", false, "emit events with no sensitive data matches")
	enrichCmd.Flags().BoolVar(&enrichFlagDebug, "debug", false, "include debug information in output")

	enrichCmd.MarkFlagRequired("schema")
	enrichCmd.MarkFlagRequired("dict")
	enrichCmd.MarkFlagRequired("risk")
}

func runEnrich(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	startTime := time.Now()

	logger.L().Infow("Starting enrichment process",
		"schema_file", enrichFlagSchema,
		"dict_file", enrichFlagDict,
		"risk_file", enrichFlagRisk,
		"input", enrichFlagInput,
		"output", enrichFlagOutput,
		"emit_unknown", enrichFlagEmitUnknown,
		"debug", enrichFlagDebug)

	// Load schema
	logger.L().Debugw("Loading database schema", "file", enrichFlagSchema)
	schema, err := enrich.LoadSchemaCSV(enrichFlagSchema)
	if err != nil {
		return fmt.Errorf("failed to load schema: %w", err)
	}

	// Load sensitivity dictionary
	logger.L().Debugw("Loading sensitivity dictionary", "file", enrichFlagDict)
	dict, err := enrich.LoadDict(enrichFlagDict)
	if err != nil {
		return fmt.Errorf("failed to load sensitivity dictionary: %w", err)
	}

	// Load risk scoring
	logger.L().Debugw("Loading risk scoring policy", "file", enrichFlagRisk)
	riskScoring, err := enrich.LoadRisk(enrichFlagRisk, dict.CategoryNames)
	if err != nil {
		return fmt.Errorf("failed to load risk scoring: %w", err)
	}

	// Create enricher
	enricherOptions := enrich.EnrichmentOptions{
		EmitUnknown: enrichFlagEmitUnknown,
		Debug:       enrichFlagDebug,
	}

	enricher := enrich.NewEnricher(schema, dict, riskScoring, enricherOptions)

	// Log enricher statistics
	stats := enricher.GetStats()
	logger.L().Debugw("Enricher initialized",
		"stats", stats)

	// Setup input reader
	var input io.Reader = os.Stdin
	if enrichFlagInput != "" {
		file, err := os.Open(enrichFlagInput)
		if err != nil {
			return fmt.Errorf("failed to open input file %s: %w", enrichFlagInput, err)
		}
		defer file.Close()
		input = file
		logger.L().Debugw("Reading from input file", "file", enrichFlagInput)
	} else {
		logger.L().Debug("Reading from stdin")
	}

	// Setup output writer
	var output io.Writer = os.Stdout
	if enrichFlagOutput != "" {
		file, err := os.Create(enrichFlagOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", enrichFlagOutput, err)
		}
		defer file.Close()
		output = file
		logger.L().Debugw("Writing to output file", "file", enrichFlagOutput)
	} else {
		logger.L().Debug("Writing to stdout")
	}

	// Process events
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	var metrics EnrichmentMetrics
	metrics.init() // Initialize maps
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse input JSON
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			metrics.ParseErrors++
			logger.L().Warnw("Failed to parse input JSON",
				"line", lineNumber,
				"line_content", line,
				"error", err)

			// Emit error event instead of dropping the line
			errorEvent := createErrorEvent(line, "enrich", fmt.Sprintf("JSON parse error: %v", err))
			if errorJSON, marshalErr := json.Marshal(errorEvent); marshalErr == nil {
				if _, writeErr := writer.WriteString(string(errorJSON) + "\n"); writeErr != nil {
					return fmt.Errorf("failed to write error event: %w", writeErr)
				}
				metrics.OutputEvents++
				metrics.ErrorEvents++
			}
			continue
		}

		metrics.InputEvents++

		// Process the event
		result := enricher.ProcessEvent(event)
		if result.Error != nil {
			metrics.EnrichmentErrors++
			logger.L().Errorw("Failed to enrich event",
				"line", lineNumber,
				"event_id", getEventID(event),
				"error", result.Error)

			// Emit error event instead of dropping the event
			errorEvent := createErrorEventFromEvent(event, "enrich", fmt.Sprintf("Enrichment error: %v", result.Error))
			if errorJSON, marshalErr := json.Marshal(errorEvent); marshalErr == nil {
				if _, writeErr := writer.WriteString(string(errorJSON) + "\n"); writeErr != nil {
					return fmt.Errorf("failed to write error event: %w", writeErr)
				}
				metrics.OutputEvents++
				metrics.ErrorEvents++
			}
			continue
		}

		// Update metrics
		if result.ShouldEmit {
			metrics.OutputEvents++
			if len(result.Categories) > 0 {
				metrics.SensitiveEvents++
				for _, category := range result.Categories {
					metrics.CategoryCounts[category]++
				}
			} else {
				metrics.UnknownEvents++
			}

			// Update risk level counts
			metrics.RiskLevelCounts[result.RiskLevel]++

			// Check for bulk operations
			if bulk, exists := result.EnrichedEvent["bulk"].(bool); exists && bulk {
				metrics.BulkEvents++
			}

			// Write enriched event
			enrichedJSON, err := json.Marshal(result.EnrichedEvent)
			if err != nil {
				metrics.SerializationErrors++
				logger.L().Errorw("Failed to serialize enriched event",
					"line", lineNumber,
					"event_id", getEventID(event),
					"error", err)

				// Emit error event instead of dropping the event
				errorEvent := createErrorEventFromEvent(event, "enrich", fmt.Sprintf("Serialization error: %v", err))
				if errorJSON, marshalErr := json.Marshal(errorEvent); marshalErr == nil {
					if _, writeErr := writer.WriteString(string(errorJSON) + "\n"); writeErr != nil {
						return fmt.Errorf("failed to write error event: %w", writeErr)
					}
					metrics.OutputEvents++
					metrics.ErrorEvents++
				}
				continue
			}

			if _, err := writer.WriteString(string(enrichedJSON) + "\n"); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		} else {
			metrics.DroppedEvents++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	// Flush output
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush output: %w", err)
	}

	duration := time.Since(startTime)

	// Log final metrics
	logger.L().Infow("Enrichment completed",
		"duration", duration,
		"input_events", metrics.InputEvents,
		"output_events", metrics.OutputEvents,
		"sensitive_events", metrics.SensitiveEvents,
		"unknown_events", metrics.UnknownEvents,
		"dropped_events", metrics.DroppedEvents,
		"bulk_events", metrics.BulkEvents,
		"error_events", metrics.ErrorEvents,
		"parse_errors", metrics.ParseErrors,
		"enrichment_errors", metrics.EnrichmentErrors,
		"serialization_errors", metrics.SerializationErrors,
		"category_counts", metrics.CategoryCounts,
		"risk_level_counts", metrics.RiskLevelCounts)

	// Write summary to run log
	if err := writeRunLogSummary(cfg, metrics, duration, startTime); err != nil {
		logger.L().Warnw("Failed to write run log summary", "error", err)
	}

	return nil
}

// EnrichmentMetrics tracks statistics during the enrichment process
type EnrichmentMetrics struct {
	InputEvents         int            `json:"input_events"`
	OutputEvents        int            `json:"output_events"`
	SensitiveEvents     int            `json:"sensitive_events"`
	UnknownEvents       int            `json:"unknown_events"`
	DroppedEvents       int            `json:"dropped_events"`
	BulkEvents          int            `json:"bulk_events"`
	ErrorEvents         int            `json:"error_events"`
	ParseErrors         int            `json:"parse_errors"`
	EnrichmentErrors    int            `json:"enrichment_errors"`
	SerializationErrors int            `json:"serialization_errors"`
	CategoryCounts      map[string]int `json:"category_counts"`
	RiskLevelCounts     map[string]int `json:"risk_level_counts"`
}

// Initialize metrics with empty maps
func (m *EnrichmentMetrics) init() {
	if m.CategoryCounts == nil {
		m.CategoryCounts = make(map[string]int)
	}
	if m.RiskLevelCounts == nil {
		m.RiskLevelCounts = make(map[string]int)
	}
}

// writeRunLogSummary appends a summary entry to the run log file
func writeRunLogSummary(cfg *config.Config, metrics EnrichmentMetrics, duration time.Duration, startTime time.Time) error {
	if cfg.Logging.RunLog == "" {
		return nil // No run log configured
	}

	// Ensure metrics maps are initialized
	metrics.init()

	// Create summary in the format specified by the enrich instructions
	summary := map[string]interface{}{
		"stage": "enrich",
		"ts":    startTime.Format(time.RFC3339),
		"counters": map[string]interface{}{
			"input_events":    metrics.InputEvents,
			"enriched_events": metrics.SensitiveEvents,
			"unknown_events":  metrics.UnknownEvents,
			"dropped_events":  metrics.DroppedEvents,
			"error_events":    metrics.ErrorEvents,
		},
	}

	// Add optional detailed metrics for debugging/analysis
	if enrichFlagDebug {
		summary["duration_ms"] = duration.Seconds() * 1000 // Convert to fractional milliseconds
		summary["detailed_metrics"] = metrics
		summary["config"] = map[string]interface{}{
			"schema_file":  enrichFlagSchema,
			"dict_file":    enrichFlagDict,
			"risk_file":    enrichFlagRisk,
			"input_file":   enrichFlagInput,
			"output_file":  enrichFlagOutput,
			"emit_unknown": enrichFlagEmitUnknown,
			"debug":        enrichFlagDebug,
		}
	}

	// Open run log file for appending
	file, err := os.OpenFile(cfg.Logging.RunLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open run log file: %w", err)
	}
	defer file.Close()

	// Write summary as NDJSON
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("failed to marshal run log summary: %w", err)
	}

	if _, err := file.WriteString(string(summaryJSON) + "\n"); err != nil {
		return fmt.Errorf("failed to write run log summary: %w", err)
	}

	return nil
}

// getEventID extracts the event ID from an event, with fallback to empty string
func getEventID(event map[string]interface{}) string {
	if eventID, exists := event["event_id"]; exists {
		if id, ok := eventID.(string); ok {
			return id
		}
	}
	return ""
}

// createErrorEvent creates an error event from a raw line that failed to parse
func createErrorEvent(rawLine, phase, message string) map[string]interface{} {
	return map[string]interface{}{
		"event_id":   generateErrorEventID(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"query_type": "ERROR",
		"raw_query":  rawLine,
		"error": map[string]interface{}{
			"phase":   phase,
			"message": message,
		},
	}
}

// createErrorEventFromEvent creates an error event from a parsed event that failed during enrichment
func createErrorEventFromEvent(originalEvent map[string]interface{}, phase, message string) map[string]interface{} {
	errorEvent := map[string]interface{}{
		"query_type": "ERROR",
		"error": map[string]interface{}{
			"phase":   phase,
			"message": message,
		},
	}

	// Copy key fields from original event if they exist
	if eventID, exists := originalEvent["event_id"]; exists {
		errorEvent["event_id"] = eventID
	} else {
		errorEvent["event_id"] = generateErrorEventID()
	}

	if timestamp, exists := originalEvent["timestamp"]; exists {
		errorEvent["timestamp"] = timestamp
	} else {
		errorEvent["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}

	if rawQuery, exists := originalEvent["raw_query"]; exists {
		errorEvent["raw_query"] = rawQuery
	}

	if dbSystem, exists := originalEvent["db_system"]; exists {
		errorEvent["db_system"] = dbSystem
	}

	if dbUser, exists := originalEvent["db_user"]; exists {
		errorEvent["db_user"] = dbUser
	}

	return errorEvent
}

// generateErrorEventID generates a unique event ID for error events
func generateErrorEventID() string {
	return fmt.Sprintf("error-%d", time.Now().UnixNano())
}

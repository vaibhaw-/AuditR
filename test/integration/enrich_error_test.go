package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrichIntegration_ErrorEmission tests error event emission
func TestEnrichIntegration_ErrorEmission(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	t.Run("json_parse_errors", func(t *testing.T) {
		// Create input with invalid JSON lines
		testInput := `{"event_id": "valid-1", "timestamp": "2025-01-01T12:00:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT 1;"}
invalid json line here
{"event_id": "valid-2", "timestamp": "2025-01-01T12:01:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT 2;"}
{incomplete json
{"event_id": "valid-3", "timestamp": "2025-01-01T12:02:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT 3;"}`

		inputFile := filepath.Join(projectRoot, fmt.Sprintf("test_error_input_%d.jsonl", time.Now().Unix()))
		err := os.WriteFile(inputFile, []byte(testInput), 0644)
		require.NoError(t, err)
		defer os.Remove(inputFile)

		outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_error_output_%d.jsonl", time.Now().Unix()))
		defer os.Remove(outputFile)

		// Run enrichment
		cmd := exec.Command(binaryPath, "enrich",
			"--schema", filepath.Join(projectRoot, "postgres_schema.csv"),
			"--dict", filepath.Join(projectRoot, "cmd/auditr/config/sensitivity_dict_extended.json"),
			"--risk", filepath.Join(projectRoot, "cmd/auditr/config/risk_scoring.json"),
			"--input", inputFile,
			"--output", outputFile,
			"--emit-unknown")

		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()

		// Command should succeed despite parse errors
		if err != nil {
			t.Logf("Command output: %s", string(output))
		}
		require.NoError(t, err, "Command should succeed despite parse errors")

		// Parse output
		enrichedEvents := parseJSONLFile(t, outputFile)
		require.Len(t, enrichedEvents, 5, "Should have 5 events: 3 valid + 2 error events")

		// Count error events
		errorCount := 0
		validCount := 0

		for _, event := range enrichedEvents {
			queryType, _ := event["query_type"].(string)
			if queryType == "ERROR" {
				errorCount++

				// Validate error event structure
				assert.Contains(t, event, "event_id", "Error event should have event_id")
				assert.Contains(t, event, "timestamp", "Error event should have timestamp")
				assert.Contains(t, event, "raw_query", "Error event should have raw_query")
				assert.Contains(t, event, "error", "Error event should have error field")

				errorInfo, ok := event["error"].(map[string]interface{})
				require.True(t, ok, "Error field should be an object")
				assert.Equal(t, "enrich", errorInfo["phase"], "Error phase should be 'enrich'")
				assert.Contains(t, errorInfo["message"].(string), "JSON parse error", "Error message should mention JSON parse error")

				t.Logf("✅ Error event: %s", event["event_id"])
			} else {
				validCount++
			}
		}

		assert.Equal(t, 2, errorCount, "Should have 2 error events")
		assert.Equal(t, 3, validCount, "Should have 3 valid events")

		t.Logf("✅ Error handling test: %d error events, %d valid events", errorCount, validCount)
	})

	t.Run("enrichment_errors", func(t *testing.T) {
		// Create a scenario that might cause enrichment errors
		// For example, events with missing required fields
		testEvents := []map[string]interface{}{
			{
				"event_id":   "missing-query-1",
				"timestamp":  "2025-01-01T12:00:00Z",
				"db_system":  "postgres",
				"query_type": "SELECT",
				// Missing raw_query field
			},
			{
				"event_id":   "valid-1",
				"timestamp":  "2025-01-01T12:01:00Z",
				"db_system":  "postgres",
				"query_type": "SELECT",
				"raw_query":  "SELECT 1;",
			},
		}

		inputFile := createTestInputFromEvents(t, projectRoot, testEvents)
		defer os.Remove(inputFile)

		outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_enrichment_error_output_%d.jsonl", time.Now().Unix()))
		defer os.Remove(outputFile)

		cmd := exec.Command(binaryPath, "enrich",
			"--schema", filepath.Join(projectRoot, "postgres_schema.csv"),
			"--dict", filepath.Join(projectRoot, "cmd/auditr/config/sensitivity_dict_extended.json"),
			"--risk", filepath.Join(projectRoot, "cmd/auditr/config/risk_scoring.json"),
			"--input", inputFile,
			"--output", outputFile,
			"--emit-unknown")

		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("Command output: %s", string(output))
		}
		require.NoError(t, err, "Command should succeed despite enrichment issues")

		enrichedEvents := parseJSONLFile(t, outputFile)
		require.Len(t, enrichedEvents, 2, "Should have 2 events")

		// The event with missing raw_query should still be processed (enrichment is resilient)
		// But let's verify both events are handled properly
		for _, event := range enrichedEvents {
			eventID := event["event_id"].(string)
			t.Logf("Processed event: %s", eventID)
		}
	})

	t.Run("mixed_valid_and_invalid", func(t *testing.T) {
		// Mix of valid events, invalid JSON, and edge cases
		testInput := `{"event_id": "valid-1", "timestamp": "2025-01-01T12:00:00Z", "db_system": "postgres", "query_type": "INSERT", "raw_query": "INSERT INTO healthcare.patient (ssn, email) VALUES ('123-45-6789', 'test@example.com');", "bulk": false}
malformed line 1
{"event_id": "valid-2", "timestamp": "2025-01-01T12:01:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT * FROM healthcare.patient;", "bulk": true, "bulk_type": "export", "full_table_read": true}
{broken json
{"event_id": "valid-3", "timestamp": "2025-01-01T12:02:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT version();", "bulk": false}`

		inputFile := filepath.Join(projectRoot, fmt.Sprintf("test_mixed_input_%d.jsonl", time.Now().Unix()))
		err := os.WriteFile(inputFile, []byte(testInput), 0644)
		require.NoError(t, err)
		defer os.Remove(inputFile)

		outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_mixed_output_%d.jsonl", time.Now().Unix()))
		defer os.Remove(outputFile)

		cmd := exec.Command(binaryPath, "enrich",
			"--schema", filepath.Join(projectRoot, "postgres_schema.csv"),
			"--dict", filepath.Join(projectRoot, "cmd/auditr/config/sensitivity_dict_extended.json"),
			"--risk", filepath.Join(projectRoot, "cmd/auditr/config/risk_scoring.json"),
			"--input", inputFile,
			"--output", outputFile,
			"--emit-unknown",
			"--debug")

		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("Command output: %s", string(output))
		}
		require.NoError(t, err, "Mixed input test should succeed")

		enrichedEvents := parseJSONLFile(t, outputFile)
		require.Len(t, enrichedEvents, 5, "Should have 5 events: 3 valid + 2 error")

		// Analyze results
		stats := analyzeEnrichedEvents(t, enrichedEvents)
		errorCount := 0
		sensitiveCount := 0
		bulkCount := 0

		for _, event := range enrichedEvents {
			queryType, _ := event["query_type"].(string)
			if queryType == "ERROR" {
				errorCount++
			} else {
				// Check for sensitive data
				if sensitivity, exists := event["sensitivity"]; exists {
					if sensArray, ok := sensitivity.([]interface{}); ok && len(sensArray) > 0 {
						sensitiveCount++
					}
				}

				// Check for bulk operations
				if bulk, exists := event["bulk"]; exists && bulk.(bool) {
					bulkCount++
				}
			}
		}

		t.Logf("📊 Mixed Input Results:")
		t.Logf("  Total events: %d", len(enrichedEvents))
		t.Logf("  Error events: %d", errorCount)
		t.Logf("  Sensitive events: %d", sensitiveCount)
		t.Logf("  Bulk events: %d", bulkCount)
		t.Logf("  Categories found: %v", stats.CategoriesFound)

		assert.Equal(t, 2, errorCount, "Should have 2 error events")
		assert.GreaterOrEqual(t, sensitiveCount, 1, "Should have at least 1 sensitive event (PII)")
		assert.GreaterOrEqual(t, bulkCount, 1, "Should have at least 1 bulk event (SELECT *)")
	})
}

// TestEnrichIntegration_ErrorEventStructure validates the structure of error events
func TestEnrichIntegration_ErrorEventStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create input with various error scenarios
	testInput := `invalid json without quotes
{"incomplete": "json"
not json at all!
{"valid": "event", "event_id": "test-1", "timestamp": "2025-01-01T12:00:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT 1;"}`

	inputFile := filepath.Join(projectRoot, fmt.Sprintf("test_structure_input_%d.jsonl", time.Now().Unix()))
	err = os.WriteFile(inputFile, []byte(testInput), 0644)
	require.NoError(t, err)
	defer os.Remove(inputFile)

	outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_structure_output_%d.jsonl", time.Now().Unix()))
	defer os.Remove(outputFile)

	cmd := exec.Command(binaryPath, "enrich",
		"--schema", filepath.Join(projectRoot, "postgres_schema.csv"),
		"--dict", filepath.Join(projectRoot, "cmd/auditr/config/sensitivity_dict_extended.json"),
		"--risk", filepath.Join(projectRoot, "cmd/auditr/config/risk_scoring.json"),
		"--input", inputFile,
		"--output", outputFile,
		"--emit-unknown")

	cmd.Dir = projectRoot
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	enrichedEvents := parseJSONLFile(t, outputFile)
	require.Len(t, enrichedEvents, 4, "Should have 4 events: 1 valid + 3 error")

	// Validate error event structure
	errorEvents := make([]map[string]interface{}, 0)
	for _, event := range enrichedEvents {
		if queryType, _ := event["query_type"].(string); queryType == "ERROR" {
			errorEvents = append(errorEvents, event)
		}
	}

	require.Len(t, errorEvents, 3, "Should have 3 error events")

	for i, errorEvent := range errorEvents {
		t.Logf("Validating error event %d", i+1)

		// Required fields
		assert.Contains(t, errorEvent, "event_id", "Error event should have event_id")
		assert.Contains(t, errorEvent, "timestamp", "Error event should have timestamp")
		assert.Contains(t, errorEvent, "query_type", "Error event should have query_type")
		assert.Contains(t, errorEvent, "raw_query", "Error event should have raw_query")
		assert.Contains(t, errorEvent, "error", "Error event should have error field")

		// Validate query_type
		assert.Equal(t, "ERROR", errorEvent["query_type"], "Query type should be ERROR")

		// Validate error structure
		errorInfo, ok := errorEvent["error"].(map[string]interface{})
		require.True(t, ok, "Error field should be an object")
		assert.Contains(t, errorInfo, "phase", "Error should have phase")
		assert.Contains(t, errorInfo, "message", "Error should have message")
		assert.Equal(t, "enrich", errorInfo["phase"], "Error phase should be 'enrich'")

		// Validate event_id format
		eventID := errorEvent["event_id"].(string)
		assert.True(t, strings.HasPrefix(eventID, "error-"), "Error event ID should start with 'error-'")

		// Validate timestamp format
		timestamp := errorEvent["timestamp"].(string)
		_, err := time.Parse(time.RFC3339, timestamp)
		assert.NoError(t, err, "Timestamp should be valid RFC3339 format")

		t.Logf("✅ Error event %d structure is valid", i+1)
	}
}

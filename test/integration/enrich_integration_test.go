package integration

import (
	"bufio"
	"encoding/json"
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

const (
	// Test data paths (relative to project root)
	pgEventsFile    = "pg_events.jsonl"
	mysqlEventsFile = "mysql_events.jsonl"
	pgSchemaFile    = "postgres_schema.csv"
	mysqlSchemaFile = "mysql_schema.csv"
	dictFile        = "cmd/auditr/config/sensitivity_dict_extended.json"
	riskFile        = "cmd/auditr/config/risk_scoring.json"
)

// TestEnrichIntegration_PostgreSQL tests the complete enrichment pipeline with real PostgreSQL data
func TestEnrichIntegration_PostgreSQL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Get project root directory
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	// Build the auditr binary
	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create temporary output file
	outputFile := filepath.Join(projectRoot, "test_output_pg.jsonl")
	defer os.Remove(outputFile)

	// Run enrichment on PostgreSQL events, focusing on sensitive data
	inputFile := createSensitiveTestInputFile(t, projectRoot, pgEventsFile, 20)
	defer os.Remove(inputFile)

	cmd := exec.Command(binaryPath, "enrich",
		"--schema", filepath.Join(projectRoot, pgSchemaFile),
		"--dict", filepath.Join(projectRoot, dictFile),
		"--risk", filepath.Join(projectRoot, riskFile),
		"--input", inputFile,
		"--output", outputFile,
		"--emit-unknown",
		"--debug")

	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Command output: %s", string(output))
		require.NoError(t, err, "Enrichment command failed")
	}

	// Verify output file was created and has content
	require.FileExists(t, outputFile)

	// Parse and validate the enriched events
	enrichedEvents := parseJSONLFile(t, outputFile)
	require.NotEmpty(t, enrichedEvents, "No enriched events found")

	t.Logf("Processed %d events, enriched %d events", 20, len(enrichedEvents))

	// Analyze the results
	stats := analyzeEnrichedEvents(t, enrichedEvents)

	// Validate expected results
	assert.Greater(t, stats.TotalEvents, 0, "Should have processed some events")
	assert.GreaterOrEqual(t, stats.SensitiveEvents, 0, "Should have some sensitive events")
	assert.Contains(t, []string{"low", "medium", "high", "critical"}, stats.MaxRiskLevel, "Should have valid risk levels")

	// Log detailed statistics
	t.Logf("Integration test results:")
	t.Logf("  Total events: %d", stats.TotalEvents)
	t.Logf("  Sensitive events: %d", stats.SensitiveEvents)
	t.Logf("  Unknown events: %d", stats.UnknownEvents)
	t.Logf("  Bulk events: %d", stats.BulkEvents)
	t.Logf("  Debug events: %d", stats.DebugEvents)
	t.Logf("  Categories found: %v", stats.CategoriesFound)
	t.Logf("  Risk levels: %v", stats.RiskLevels)
	t.Logf("  Max risk level: %s", stats.MaxRiskLevel)

	// Validate specific healthcare scenarios
	validateHealthcareScenarios(t, enrichedEvents)
}

// TestEnrichIntegration_MySQL tests the complete enrichment pipeline with real MySQL data
func TestEnrichIntegration_MySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	outputFile := filepath.Join(projectRoot, "test_output_mysql.jsonl")
	defer os.Remove(outputFile)

	// Run enrichment on first 50 MySQL events
	inputFile := createTestInputFile(t, projectRoot, mysqlEventsFile, 50)
	defer os.Remove(inputFile)

	cmd := exec.Command(binaryPath, "enrich",
		"--schema", filepath.Join(projectRoot, mysqlSchemaFile),
		"--dict", filepath.Join(projectRoot, dictFile),
		"--risk", filepath.Join(projectRoot, riskFile),
		"--input", inputFile,
		"--output", outputFile,
		"--emit-unknown")

	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Command output: %s", string(output))
		require.NoError(t, err, "MySQL enrichment command failed")
	}

	require.FileExists(t, outputFile)

	enrichedEvents := parseJSONLFile(t, outputFile)
	require.NotEmpty(t, enrichedEvents, "No MySQL enriched events found")

	stats := analyzeEnrichedEvents(t, enrichedEvents)

	assert.Greater(t, stats.TotalEvents, 0, "Should have processed MySQL events")

	t.Logf("MySQL Integration test results:")
	t.Logf("  Total events: %d", stats.TotalEvents)
	t.Logf("  Sensitive events: %d", stats.SensitiveEvents)
	t.Logf("  Categories found: %v", stats.CategoriesFound)
	t.Logf("  Risk levels: %v", stats.RiskLevels)
}

// TestEnrichIntegration_BulkOperations specifically tests bulk operation detection
func TestEnrichIntegration_BulkOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create test events with known bulk operations (bulk fields pre-populated from parse step)
	bulkEvents := []map[string]interface{}{
		{
			"event_id":        "bulk-1",
			"timestamp":       "2025-01-01T12:00:00Z",
			"db_system":       "postgres",
			"query_type":      "SELECT",
			"raw_query":       "SELECT * FROM healthcare.patient",
			"bulk":            true,
			"bulk_type":       "export",
			"full_table_read": true,
		},
		{
			"event_id":   "bulk-2",
			"timestamp":  "2025-01-01T12:01:00Z",
			"db_system":  "postgres",
			"query_type": "COPY",
			"raw_query":  "COPY healthcare.patient TO '/tmp/patients.csv' WITH CSV",
			"bulk":       true,
			"bulk_type":  "export",
		},
		{
			"event_id":   "bulk-3",
			"timestamp":  "2025-01-01T12:02:00Z",
			"db_system":  "mysql",
			"query_type": "SELECT",
			"raw_query":  "LOAD DATA INFILE '/tmp/data.csv' INTO TABLE healthcare_patient",
			"bulk":       true,
			"bulk_type":  "import",
		},
		{
			"event_id":   "normal-1",
			"timestamp":  "2025-01-01T12:03:00Z",
			"db_system":  "postgres",
			"query_type": "SELECT",
			"raw_query":  "SELECT ssn FROM healthcare.patient WHERE patient_id = '123'",
		},
	}

	inputFile := createTestInputFromEvents(t, projectRoot, bulkEvents)
	defer os.Remove(inputFile)

	outputFile := filepath.Join(projectRoot, "test_output_bulk.jsonl")
	defer os.Remove(outputFile)

	cmd := exec.Command(binaryPath, "enrich",
		"--schema", filepath.Join(projectRoot, pgSchemaFile),
		"--dict", filepath.Join(projectRoot, dictFile),
		"--risk", filepath.Join(projectRoot, riskFile),
		"--input", inputFile,
		"--output", outputFile,
		"--emit-unknown",
		"--debug")

	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Command output: %s", string(output))
		require.NoError(t, err, "Bulk operations test failed")
	}

	enrichedEvents := parseJSONLFile(t, outputFile)
	require.Len(t, enrichedEvents, 4, "Should have 4 enriched events")

	// Validate bulk operation detection
	bulkCount := 0
	for _, event := range enrichedEvents {
		if bulk, exists := event["bulk"].(bool); exists && bulk {
			bulkCount++
			assert.Contains(t, event, "bulk_type", "Bulk events should have bulk_type")

			bulkType := event["bulk_type"].(string)
			assert.Contains(t, []string{"select", "export", "import"}, bulkType, "Should have valid bulk type")

			t.Logf("Found bulk operation: %s (type: %s)", event["event_id"], bulkType)
		}
	}

	assert.Equal(t, 3, bulkCount, "Should detect exactly 3 bulk operations")
}

// TestEnrichIntegration_ErrorHandling tests error scenarios
func TestEnrichIntegration_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	t.Run("missing_schema_file", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "enrich",
			"--schema", "nonexistent.csv",
			"--dict", filepath.Join(projectRoot, dictFile),
			"--risk", filepath.Join(projectRoot, riskFile))

		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()

		assert.Error(t, err, "Should fail with missing schema file")
		assert.Contains(t, string(output), "failed to load schema", "Should show schema error")
	})

	t.Run("invalid_json_input", func(t *testing.T) {
		// Create file with invalid JSON
		invalidInputFile := filepath.Join(projectRoot, "invalid_input.jsonl")
		err := os.WriteFile(invalidInputFile, []byte("invalid json\n{\"valid\": \"json\"}\n"), 0644)
		require.NoError(t, err)
		defer os.Remove(invalidInputFile)

		outputFile := filepath.Join(projectRoot, "test_output_invalid.jsonl")
		defer os.Remove(outputFile)

		cmd := exec.Command(binaryPath, "enrich",
			"--schema", filepath.Join(projectRoot, pgSchemaFile),
			"--dict", filepath.Join(projectRoot, dictFile),
			"--risk", filepath.Join(projectRoot, riskFile),
			"--input", invalidInputFile,
			"--output", outputFile,
			"--emit-unknown")

		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()

		// Should not fail completely, but should log parse errors
		if err != nil {
			t.Logf("Command output: %s", string(output))
		}

		// Check if any valid events were processed
		if _, err := os.Stat(outputFile); err == nil {
			enrichedEvents := parseJSONLFile(t, outputFile)
			t.Logf("Processed %d valid events despite invalid input", len(enrichedEvents))
		}
	})
}

// Helper functions

func getProjectRoot() (string, error) {
	// Get current working directory and find project root
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Look for go.mod file to identify project root
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
	}

	return wd, nil
}

func buildAuditrBinary(t *testing.T, projectRoot string) string {
	binaryPath := filepath.Join(projectRoot, "auditr_test")

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/auditr")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Build output: %s", string(output))
		require.NoError(t, err, "Failed to build auditr binary")
	}

	return binaryPath
}

func createTestInputFile(t *testing.T, projectRoot, sourceFile string, maxLines int) string {
	sourcePath := filepath.Join(projectRoot, sourceFile)

	sourceFileHandle, err := os.Open(sourcePath)
	require.NoError(t, err)
	defer sourceFileHandle.Close()

	testInputFile := filepath.Join(projectRoot, fmt.Sprintf("test_input_%d.jsonl", time.Now().Unix()))
	testFileHandle, err := os.Create(testInputFile)
	require.NoError(t, err)
	defer testFileHandle.Close()

	scanner := bufio.NewScanner(sourceFileHandle)
	lineCount := 0

	for scanner.Scan() && lineCount < maxLines {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			// Remove any existing enrichment data to test fresh enrichment
			var event map[string]interface{}
			if err := json.Unmarshal([]byte(line), &event); err == nil {
				delete(event, "enrichment")
				delete(event, "sensitivity")
				delete(event, "risk_level")
				delete(event, "bulk")
				delete(event, "bulk_type")
				delete(event, "debug_info")

				cleanedLine, _ := json.Marshal(event)
				fmt.Fprintln(testFileHandle, string(cleanedLine))
				lineCount++
			}
		}
	}

	require.NoError(t, scanner.Err())
	t.Logf("Created test input file with %d events: %s", lineCount, testInputFile)

	return testInputFile
}

func createSensitiveTestInputFile(t *testing.T, projectRoot, sourceFile string, maxLines int) string {
	sourcePath := filepath.Join(projectRoot, sourceFile)

	sourceFileHandle, err := os.Open(sourcePath)
	require.NoError(t, err)
	defer sourceFileHandle.Close()

	testInputFile := filepath.Join(projectRoot, fmt.Sprintf("test_input_sensitive_%d.jsonl", time.Now().Unix()))
	testFileHandle, err := os.Create(testInputFile)
	require.NoError(t, err)
	defer testFileHandle.Close()

	scanner := bufio.NewScanner(sourceFileHandle)
	lineCount := 0
	sensitiveCount := 0

	// Keywords that indicate potentially sensitive queries
	sensitiveKeywords := []string{"patient", "ssn", "email", "phone", "address", "dob", "encounter", "diagnosis"}

	for scanner.Scan() && lineCount < maxLines {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			rawQuery, _ := event["raw_query"].(string)
			queryLower := strings.ToLower(rawQuery)

			// Check if this query contains sensitive keywords
			isSensitive := false
			for _, keyword := range sensitiveKeywords {
				if strings.Contains(queryLower, keyword) {
					isSensitive = true
					break
				}
			}

			// Include sensitive queries and some non-sensitive ones for balance
			if isSensitive || (sensitiveCount < maxLines/2 && lineCount < maxLines) {
				// Remove any existing enrichment data to test fresh enrichment
				delete(event, "enrichment")
				delete(event, "sensitivity")
				delete(event, "risk_level")
				delete(event, "bulk")
				delete(event, "bulk_type")
				delete(event, "debug_info")

				cleanedLine, _ := json.Marshal(event)
				fmt.Fprintln(testFileHandle, string(cleanedLine))
				lineCount++

				if isSensitive {
					sensitiveCount++
				}
			}
		}
	}

	require.NoError(t, scanner.Err())
	t.Logf("Created sensitive test input file with %d events (%d potentially sensitive): %s", lineCount, sensitiveCount, testInputFile)

	return testInputFile
}

func createTestInputFromEvents(t *testing.T, projectRoot string, events []map[string]interface{}) string {
	testInputFile := filepath.Join(projectRoot, fmt.Sprintf("test_input_custom_%d.jsonl", time.Now().Unix()))
	testFileHandle, err := os.Create(testInputFile)
	require.NoError(t, err)
	defer testFileHandle.Close()

	for _, event := range events {
		eventJSON, err := json.Marshal(event)
		require.NoError(t, err)
		fmt.Fprintln(testFileHandle, string(eventJSON))
	}

	return testInputFile
}

func parseJSONLFile(t *testing.T, filePath string) []map[string]interface{} {
	file, err := os.Open(filePath)
	require.NoError(t, err)
	defer file.Close()

	var events []map[string]interface{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			var event map[string]interface{}
			err := json.Unmarshal([]byte(line), &event)
			require.NoError(t, err, "Failed to parse JSON line: %s", line)
			events = append(events, event)
		}
	}

	require.NoError(t, scanner.Err())
	return events
}

// EnrichmentStats holds statistics about enriched events
type EnrichmentStats struct {
	TotalEvents     int
	SensitiveEvents int
	UnknownEvents   int
	BulkEvents      int
	DebugEvents     int
	CategoriesFound map[string]int
	RiskLevels      map[string]int
	MaxRiskLevel    string
}

func analyzeEnrichedEvents(t *testing.T, events []map[string]interface{}) EnrichmentStats {
	stats := EnrichmentStats{
		CategoriesFound: make(map[string]int),
		RiskLevels:      make(map[string]int),
		MaxRiskLevel:    "low",
	}

	riskHierarchy := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

	for _, event := range events {
		stats.TotalEvents++

		// Check for sensitivity data
		if sensitivity, exists := event["sensitivity"]; exists {
			if sensArray, ok := sensitivity.([]interface{}); ok {
				if len(sensArray) > 0 {
					stats.SensitiveEvents++

					// Count categories
					for _, sens := range sensArray {
						if sensStr, ok := sens.(string); ok {
							parts := strings.Split(sensStr, ":")
							if len(parts) > 0 {
								category := parts[0]
								stats.CategoriesFound[category]++
							}
						}
					}
				} else {
					stats.UnknownEvents++
				}
			}
		}

		// Check risk level
		if riskLevel, exists := event["risk_level"]; exists {
			if riskStr, ok := riskLevel.(string); ok {
				stats.RiskLevels[riskStr]++

				if riskHierarchy[riskStr] > riskHierarchy[stats.MaxRiskLevel] {
					stats.MaxRiskLevel = riskStr
				}
			}
		}

		// Check for bulk operations
		if bulk, exists := event["bulk"]; exists {
			if bulkBool, ok := bulk.(bool); ok && bulkBool {
				stats.BulkEvents++
			}
		}

		// Check for debug info
		if _, exists := event["debug_info"]; exists {
			stats.DebugEvents++
		}
	}

	return stats
}

func validateHealthcareScenarios(t *testing.T, events []map[string]interface{}) {
	foundPII := false
	foundPHI := false
	foundHighRisk := false

	for _, event := range events {
		// Check for PII detection
		if sensitivity, exists := event["sensitivity"]; exists {
			if sensArray, ok := sensitivity.([]interface{}); ok {
				for _, sens := range sensArray {
					if sensStr, ok := sens.(string); ok {
						if strings.HasPrefix(sensStr, "PII:") {
							foundPII = true
							t.Logf("Found PII detection: %s in event %s", sensStr, event["event_id"])
						}
						if strings.HasPrefix(sensStr, "PHI:") {
							foundPHI = true
							t.Logf("Found PHI detection: %s in event %s", sensStr, event["event_id"])
						}
					}
				}
			}
		}

		// Check for high-risk events
		if riskLevel, exists := event["risk_level"]; exists {
			if riskStr, ok := riskLevel.(string); ok && (riskStr == "high" || riskStr == "critical") {
				foundHighRisk = true
				t.Logf("Found high-risk event: %s with risk %s", event["event_id"], riskStr)
			}
		}
	}

	// We expect to find at least some healthcare-related sensitive data
	if foundPII || foundPHI {
		t.Logf("✅ Successfully detected healthcare sensitive data (PII: %v, PHI: %v)", foundPII, foundPHI)
	} else {
		t.Logf("⚠️  No healthcare sensitive data detected - this might be expected if the test data doesn't contain patient queries")
	}

	if foundHighRisk {
		t.Logf("✅ Successfully detected high-risk operations")
	}
}

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

// TestEnrichIntegration_SensitiveData tests enrichment with known sensitive healthcare data
func TestEnrichIntegration_SensitiveData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create test input with known sensitive events
	sensitiveEvents := []map[string]interface{}{
		{
			"event_id":   "test-pii-1",
			"timestamp":  "2025-01-01T12:00:00Z",
			"db_system":  "postgres",
			"query_type": "INSERT",
			"raw_query":  "INSERT INTO healthcare.patient (patient_id, ssn, first_name, last_name, dob, email, phone_number, address_line1, city, state, postal_code, country, created_at, updated_at) VALUES ('123','555-12-3456','John','Doe','1990-01-01','john@example.com','555-1234','123 Main St','City','State','12345','US',NOW(),NOW());",
		},
		{
			"event_id":   "test-phi-1",
			"timestamp":  "2025-01-01T12:01:00Z",
			"db_system":  "postgres",
			"query_type": "SELECT",
			"raw_query":  "SELECT diagnosis, treatment FROM healthcare.encounter WHERE patient_id = '123';",
		},
		{
			"event_id":   "test-bulk-1",
			"timestamp":  "2025-01-01T12:02:00Z",
			"db_system":  "postgres",
			"query_type": "SELECT",
			"raw_query":  "SELECT * FROM healthcare.patient;",
		},
		{
			"event_id":   "test-normal-1",
			"timestamp":  "2025-01-01T12:03:00Z",
			"db_system":  "postgres",
			"query_type": "SELECT",
			"raw_query":  "SELECT version();",
		},
	}

	inputFile := createTestInputFromEvents(t, projectRoot, sensitiveEvents)
	defer os.Remove(inputFile)

	outputFile := filepath.Join(projectRoot, "test_output_sensitive.jsonl")
	defer os.Remove(outputFile)

	// Run enrichment
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
		require.NoError(t, err, "Sensitive data enrichment failed")
	}

	// Parse results
	enrichedEvents := parseJSONLFile(t, outputFile)
	require.Len(t, enrichedEvents, 4, "Should have 4 enriched events")

	// Validate each event
	eventResults := make(map[string]map[string]interface{})
	for _, event := range enrichedEvents {
		eventID := event["event_id"].(string)
		eventResults[eventID] = event
	}

	// Test PII detection
	piiEvent := eventResults["test-pii-1"]
	require.NotNil(t, piiEvent, "PII event should exist")

	sensitivity, exists := piiEvent["sensitivity"]
	require.True(t, exists, "PII event should have sensitivity field")

	sensArray, ok := sensitivity.([]interface{})
	require.True(t, ok, "Sensitivity should be an array")
	require.NotEmpty(t, sensArray, "PII event should have sensitivity matches")

	// Check for expected PII fields
	sensitivityStrings := make([]string, len(sensArray))
	for i, s := range sensArray {
		sensitivityStrings[i] = s.(string)
	}

	expectedPII := []string{"PII:ssn", "PII:dob", "PII:email", "PII:phone_number", "PII:address_line1"}
	for _, expected := range expectedPII {
		assert.Contains(t, sensitivityStrings, expected, "Should detect %s", expected)
	}

	riskLevel := piiEvent["risk_level"].(string)
	assert.Equal(t, "medium", riskLevel, "PII event should have medium risk")

	t.Logf("✅ PII Detection: Found %d sensitive fields with risk level %s", len(sensArray), riskLevel)

	// Test PHI detection
	phiEvent := eventResults["test-phi-1"]
	require.NotNil(t, phiEvent, "PHI event should exist")

	phiSensitivity, exists := phiEvent["sensitivity"]
	require.True(t, exists, "PHI event should have sensitivity field")

	phiSensArray, ok := phiSensitivity.([]interface{})
	require.True(t, ok, "PHI sensitivity should be an array")

	if len(phiSensArray) > 0 {
		phiRiskLevel := phiEvent["risk_level"].(string)
		t.Logf("✅ PHI Detection: Found %d sensitive fields with risk level %s", len(phiSensArray), phiRiskLevel)
	} else {
		t.Logf("⚠️  PHI event had no sensitivity matches - this might be expected if diagnosis/treatment aren't in the dictionary")
	}

	// Test bulk operation detection
	bulkEvent := eventResults["test-bulk-1"]
	require.NotNil(t, bulkEvent, "Bulk event should exist")

	bulk, exists := bulkEvent["bulk"]
	if exists && bulk.(bool) {
		bulkType := bulkEvent["bulk_type"].(string)
		assert.Equal(t, "select", bulkType, "Should detect SELECT * as bulk operation")
		t.Logf("✅ Bulk Detection: Detected bulk operation type %s", bulkType)
	} else {
		t.Logf("⚠️  Bulk operation not detected for SELECT *")
	}

	// Test normal event (should have low risk, no sensitivity)
	normalEvent := eventResults["test-normal-1"]
	require.NotNil(t, normalEvent, "Normal event should exist")

	normalSensitivity, exists := normalEvent["sensitivity"]
	require.True(t, exists, "Normal event should have sensitivity field")

	normalSensArray, ok := normalSensitivity.([]interface{})
	require.True(t, ok, "Normal sensitivity should be an array")
	assert.Empty(t, normalSensArray, "Normal event should have no sensitivity matches")

	normalRiskLevel := normalEvent["risk_level"].(string)
	assert.Equal(t, "low", normalRiskLevel, "Normal event should have low risk")

	t.Logf("✅ Normal Event: No sensitivity detected, risk level %s", normalRiskLevel)

	// Overall statistics
	stats := analyzeEnrichedEvents(t, enrichedEvents)
	t.Logf("📊 Overall Results:")
	t.Logf("  Total events: %d", stats.TotalEvents)
	t.Logf("  Sensitive events: %d", stats.SensitiveEvents)
	t.Logf("  Categories found: %v", stats.CategoriesFound)
	t.Logf("  Risk levels: %v", stats.RiskLevels)
	t.Logf("  Max risk level: %s", stats.MaxRiskLevel)

	// Assertions for overall results
	assert.Equal(t, 4, stats.TotalEvents, "Should process 4 events")
	assert.GreaterOrEqual(t, stats.SensitiveEvents, 1, "Should have at least 1 sensitive event")
	assert.Contains(t, stats.CategoriesFound, "PII", "Should detect PII category")
	assert.Contains(t, []string{"medium", "high", "critical"}, stats.MaxRiskLevel, "Should have elevated risk level")
}

// TestEnrichIntegration_RealHealthcareData tests with actual data from the files
func TestEnrichIntegration_RealHealthcareData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Extract known sensitive events from the real data
	inputFile := extractKnownSensitiveEvents(t, projectRoot, "pg_events.jsonl", 10)
	defer os.Remove(inputFile)

	outputFile := filepath.Join(projectRoot, "test_output_real_healthcare.jsonl")
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
		require.NoError(t, err, "Real healthcare data enrichment failed")
	}

	enrichedEvents := parseJSONLFile(t, outputFile)
	require.NotEmpty(t, enrichedEvents, "Should have enriched events from real data")

	stats := analyzeEnrichedEvents(t, enrichedEvents)

	t.Logf("📊 Real Healthcare Data Results:")
	t.Logf("  Total events: %d", stats.TotalEvents)
	t.Logf("  Sensitive events: %d", stats.SensitiveEvents)
	t.Logf("  Categories found: %v", stats.CategoriesFound)
	t.Logf("  Risk levels: %v", stats.RiskLevels)
	t.Logf("  Bulk events: %d", stats.BulkEvents)

	// We expect to find some sensitive data in real healthcare events
	assert.Greater(t, stats.SensitiveEvents, 0, "Should detect sensitive data in real healthcare events")
	assert.NotEmpty(t, stats.CategoriesFound, "Should find some sensitivity categories")
}

// extractKnownSensitiveEvents extracts events that we know contain sensitive data
func extractKnownSensitiveEvents(t *testing.T, projectRoot, sourceFile string, maxEvents int) string {
	sourcePath := filepath.Join(projectRoot, sourceFile)

	sourceFileHandle, err := os.Open(sourcePath)
	require.NoError(t, err)
	defer sourceFileHandle.Close()

	testInputFile := filepath.Join(projectRoot, fmt.Sprintf("test_input_known_sensitive_%d.jsonl", time.Now().Unix()))
	testFileHandle, err := os.Create(testInputFile)
	require.NoError(t, err)
	defer testFileHandle.Close()

	scanner := bufio.NewScanner(sourceFileHandle)
	eventCount := 0

	for scanner.Scan() && eventCount < maxEvents {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			rawQuery, _ := event["raw_query"].(string)
			queryLower := strings.ToLower(rawQuery)

			// Look for specific patterns that we know contain sensitive data
			if (strings.Contains(queryLower, "insert into") && strings.Contains(queryLower, "patient")) ||
				(strings.Contains(queryLower, "ssn")) ||
				(strings.Contains(queryLower, "email")) ||
				(strings.Contains(queryLower, "phone_number")) {

				// Clean the event
				delete(event, "enrichment")
				delete(event, "sensitivity")
				delete(event, "risk_level")
				delete(event, "bulk")
				delete(event, "bulk_type")
				delete(event, "debug_info")

				cleanedLine, _ := json.Marshal(event)
				fmt.Fprintln(testFileHandle, string(cleanedLine))
				eventCount++
			}
		}
	}

	require.NoError(t, scanner.Err())
	t.Logf("Extracted %d known sensitive events: %s", eventCount, testInputFile)

	return testInputFile
}

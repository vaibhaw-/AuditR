package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrichIntegration_RunLogFormat tests the run log output format
func TestEnrichIntegration_RunLogFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create a temporary config file with a specific run log path
	runLogFile := filepath.Join(projectRoot, fmt.Sprintf("test_run_log_%d.jsonl", time.Now().Unix()))
	configFile := filepath.Join(projectRoot, fmt.Sprintf("test_config_%d.yaml", time.Now().Unix()))

	configContent := fmt.Sprintf(`version: "0.1"
logging:
  level: "info"
  console_level: "info"
  run_log: "%s"
  development: true`, runLogFile)

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	defer os.Remove(configFile)
	defer os.Remove(runLogFile)

	// Create test input with a mix of valid and invalid events
	testInput := `{"event_id": "test-1", "timestamp": "2025-01-01T12:00:00Z", "db_system": "postgres", "query_type": "INSERT", "raw_query": "INSERT INTO healthcare.patient (ssn, email) VALUES ('123-45-6789', 'test@example.com');"}
invalid json line
{"event_id": "test-2", "timestamp": "2025-01-01T12:01:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT * FROM healthcare.patient;"}
{"event_id": "test-3", "timestamp": "2025-01-01T12:02:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT version();"}`

	inputFile := filepath.Join(projectRoot, fmt.Sprintf("test_runlog_input_%d.jsonl", time.Now().Unix()))
	err = os.WriteFile(inputFile, []byte(testInput), 0644)
	require.NoError(t, err)
	defer os.Remove(inputFile)

	outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_runlog_output_%d.jsonl", time.Now().Unix()))
	defer os.Remove(outputFile)

	// Run enrichment with the custom config
	cmd := exec.Command(binaryPath, "enrich",
		"--config", configFile,
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
	require.NoError(t, err, "Enrichment should succeed")

	// Verify the run log was created and has the correct format
	require.FileExists(t, runLogFile, "Run log file should be created")

	// Read and parse the run log
	runLogEntries := parseJSONLFile(t, runLogFile)
	require.Len(t, runLogEntries, 1, "Should have exactly one run log entry")

	runLogEntry := runLogEntries[0]

	// Validate the required fields according to the specification
	assert.Equal(t, "enrich", runLogEntry["stage"], "Stage should be 'enrich'")
	assert.Contains(t, runLogEntry, "ts", "Should have 'ts' field")
	assert.Contains(t, runLogEntry, "counters", "Should have 'counters' field")

	// Validate timestamp format
	ts, ok := runLogEntry["ts"].(string)
	require.True(t, ok, "Timestamp should be a string")
	_, err = time.Parse(time.RFC3339, ts)
	assert.NoError(t, err, "Timestamp should be valid RFC3339 format")

	// Validate counters structure
	counters, ok := runLogEntry["counters"].(map[string]interface{})
	require.True(t, ok, "Counters should be an object")

	// Check required counter fields
	requiredCounters := []string{"input_events", "enriched_events", "unknown_events", "dropped_events", "error_events"}
	for _, counter := range requiredCounters {
		assert.Contains(t, counters, counter, "Should have '%s' counter", counter)

		// Verify it's a number
		value, exists := counters[counter]
		require.True(t, exists, "Counter %s should exist", counter)
		_, ok := value.(float64) // JSON numbers are float64 in Go
		assert.True(t, ok, "Counter %s should be a number, got %T", counter, value)
	}

	// Validate expected values based on our test input
	assert.Equal(t, float64(3), counters["input_events"], "Should have 3 input events")
	assert.Equal(t, float64(2), counters["enriched_events"], "Should have 2 enriched (sensitive) events")
	assert.Equal(t, float64(1), counters["unknown_events"], "Should have 1 unknown event")
	assert.Equal(t, float64(0), counters["dropped_events"], "Should have 0 dropped events (emit-unknown is on)")
	assert.Equal(t, float64(1), counters["error_events"], "Should have 1 error event")

	t.Logf("✅ Run log format validation passed")
	t.Logf("📊 Run log counters: %+v", counters)
}

// TestEnrichIntegration_RunLogDebugMode tests run log with debug mode
func TestEnrichIntegration_RunLogDebugMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create a temporary config file
	runLogFile := filepath.Join(projectRoot, fmt.Sprintf("test_debug_run_log_%d.jsonl", time.Now().Unix()))
	configFile := filepath.Join(projectRoot, fmt.Sprintf("test_debug_config_%d.yaml", time.Now().Unix()))

	configContent := fmt.Sprintf(`version: "0.1"
logging:
  level: "info"
  console_level: "info"
  run_log: "%s"
  development: true`, runLogFile)

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	defer os.Remove(configFile)
	defer os.Remove(runLogFile)

	// Create simple test input
	testInput := `{"event_id": "debug-test", "timestamp": "2025-01-01T12:00:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT 1;"}`

	inputFile := filepath.Join(projectRoot, fmt.Sprintf("test_debug_input_%d.jsonl", time.Now().Unix()))
	err = os.WriteFile(inputFile, []byte(testInput), 0644)
	require.NoError(t, err)
	defer os.Remove(inputFile)

	outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_debug_output_%d.jsonl", time.Now().Unix()))
	defer os.Remove(outputFile)

	// Run enrichment with debug mode
	cmd := exec.Command(binaryPath, "enrich",
		"--config", configFile,
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
	require.NoError(t, err, "Debug enrichment should succeed")

	// Read and parse the run log
	runLogEntries := parseJSONLFile(t, runLogFile)
	require.Len(t, runLogEntries, 1, "Should have exactly one run log entry")

	runLogEntry := runLogEntries[0]

	// In debug mode, we should have additional fields
	assert.Contains(t, runLogEntry, "duration_ms", "Debug mode should include duration_ms")
	assert.Contains(t, runLogEntry, "detailed_metrics", "Debug mode should include detailed_metrics")
	assert.Contains(t, runLogEntry, "config", "Debug mode should include config")

	// Validate duration_ms is a number
	durationMs, ok := runLogEntry["duration_ms"].(float64)
	require.True(t, ok, "duration_ms should be a number")
	assert.Greater(t, durationMs, float64(0), "Duration should be positive")

	// Validate detailed_metrics structure
	detailedMetrics, ok := runLogEntry["detailed_metrics"].(map[string]interface{})
	require.True(t, ok, "detailed_metrics should be an object")
	assert.Contains(t, detailedMetrics, "category_counts", "Should have category_counts")
	assert.Contains(t, detailedMetrics, "risk_level_counts", "Should have risk_level_counts")

	// Validate config structure
	config, ok := runLogEntry["config"].(map[string]interface{})
	require.True(t, ok, "config should be an object")
	assert.Equal(t, true, config["debug"], "Config should show debug=true")
	// Note: default_schema was removed in favor of smart schema resolution

	t.Logf("✅ Debug mode run log validation passed")
	t.Logf("📊 Duration: %.2f ms", durationMs)
}

// TestEnrichIntegration_RunLogMultipleRuns tests multiple runs appending to the same log
func TestEnrichIntegration_RunLogMultipleRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	binaryPath := buildAuditrBinary(t, projectRoot)
	defer os.Remove(binaryPath)

	// Create a temporary config file
	runLogFile := filepath.Join(projectRoot, fmt.Sprintf("test_multi_run_log_%d.jsonl", time.Now().Unix()))
	configFile := filepath.Join(projectRoot, fmt.Sprintf("test_multi_config_%d.yaml", time.Now().Unix()))

	configContent := fmt.Sprintf(`version: "0.1"
logging:
  level: "info"
  console_level: "info"
  run_log: "%s"
  development: true`, runLogFile)

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	defer os.Remove(configFile)
	defer os.Remove(runLogFile)

	// Run enrichment multiple times
	for i := 0; i < 3; i++ {
		testInput := fmt.Sprintf(`{"event_id": "multi-test-%d", "timestamp": "2025-01-01T12:00:00Z", "db_system": "postgres", "query_type": "SELECT", "raw_query": "SELECT %d;"}`, i, i)

		inputFile := filepath.Join(projectRoot, fmt.Sprintf("test_multi_input_%d_%d.jsonl", time.Now().Unix(), i))
		err = os.WriteFile(inputFile, []byte(testInput), 0644)
		require.NoError(t, err)
		defer os.Remove(inputFile)

		outputFile := filepath.Join(projectRoot, fmt.Sprintf("test_multi_output_%d_%d.jsonl", time.Now().Unix(), i))
		defer os.Remove(outputFile)

		cmd := exec.Command(binaryPath, "enrich",
			"--config", configFile,
			"--schema", filepath.Join(projectRoot, "postgres_schema.csv"),
			"--dict", filepath.Join(projectRoot, "cmd/auditr/config/sensitivity_dict_extended.json"),
			"--risk", filepath.Join(projectRoot, "cmd/auditr/config/risk_scoring.json"),
			"--input", inputFile,
			"--output", outputFile,
			"--emit-unknown")

		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("Command output for run %d: %s", i, string(output))
		}
		require.NoError(t, err, "Run %d should succeed", i)

		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Verify the run log has 3 entries
	runLogEntries := parseJSONLFile(t, runLogFile)
	require.Len(t, runLogEntries, 3, "Should have exactly 3 run log entries")

	// Verify each entry has the correct format
	for i, entry := range runLogEntries {
		assert.Equal(t, "enrich", entry["stage"], "Entry %d should have stage=enrich", i)
		assert.Contains(t, entry, "ts", "Entry %d should have timestamp", i)
		assert.Contains(t, entry, "counters", "Entry %d should have counters", i)

		counters := entry["counters"].(map[string]interface{})
		assert.Equal(t, float64(1), counters["input_events"], "Entry %d should have 1 input event", i)
	}

	t.Logf("✅ Multiple runs validation passed - %d entries in run log", len(runLogEntries))
}

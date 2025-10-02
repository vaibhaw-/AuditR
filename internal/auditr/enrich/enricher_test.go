package enrich

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vaibhaw-/AuditR/internal/auditr/config"
)

func createTestEnricher(emitUnknown, debug bool) *Enricher {
	// Create test schema - SchemaMap is schema_name -> table_name -> column_name -> type
	schema := SchemaMap{
		"healthcare": {
			"patient": {
				"patient_id": "UUID",
				"ssn":        "VARCHAR",
				"email":      "TEXT",
				"first_name": "VARCHAR",
				"last_name":  "VARCHAR",
			},
			"encounter": {
				"encounter_id": "UUID",
				"patient_id":   "UUID",
				"diagnosis":    "TEXT",
				"treatment":    "TEXT",
			},
			"payment_method": {
				"payment_method_id": "UUID",
				"patient_id":        "UUID",
				"card_last4":        "CHAR",
				"card_network":      "VARCHAR",
			},
		},
		"payments": {
			"payment_method": {
				"payment_method_id": "UUID",
				"patient_id":        "UUID",
				"card_last4":        "CHAR",
				"card_network":      "VARCHAR",
			},
		},
		"public": {
			"system_table": {
				"id":   "INT",
				"name": "VARCHAR",
			},
		},
	}

	// Create test dictionary
	dict := &CompiledSensitivityDict{
		Categories:    make(map[string][]CompiledRule),
		CategoryNames: []string{"PII", "PHI", "Financial"},
	}

	// Add PII rules
	ssnRule := CompiledRule{
		Regex:         "(?i)^ssn$",
		ExpectedTypes: []string{"VARCHAR", "CHAR"},
		SamplePattern: "",
		CompiledRegex: regexp.MustCompile("(?i)^ssn$"),
	}
	emailRule := CompiledRule{
		Regex:         "(?i)^email$",
		ExpectedTypes: []string{"VARCHAR", "TEXT"},
		SamplePattern: "",
		CompiledRegex: regexp.MustCompile("(?i)^email$"),
	}
	dict.Categories["PII"] = []CompiledRule{ssnRule, emailRule}

	// Add PHI rules
	diagnosisRule := CompiledRule{
		Regex:         "(?i)^diagnosis$",
		ExpectedTypes: []string{"TEXT"},
		SamplePattern: "",
		CompiledRegex: regexp.MustCompile("(?i)^diagnosis$"),
	}
	treatmentRule := CompiledRule{
		Regex:         "(?i)^treatment$",
		ExpectedTypes: []string{"TEXT"},
		SamplePattern: "",
		CompiledRegex: regexp.MustCompile("(?i)^treatment$"),
	}
	dict.Categories["PHI"] = []CompiledRule{diagnosisRule, treatmentRule}

	// Add Financial rules
	cardRule := CompiledRule{
		Regex:         "(?i)^card_last4$",
		ExpectedTypes: []string{"CHAR", "VARCHAR"},
		SamplePattern: "",
		CompiledRegex: regexp.MustCompile("(?i)^card_last4$"),
	}
	dict.Categories["Financial"] = []CompiledRule{cardRule}

	// Add negative rule
	negRule := CompiledNegativeRule{
		Regex:         "(?i)^system_",
		Reason:        "System fields",
		CompiledRegex: regexp.MustCompile("(?i)^system_"),
	}
	dict.Negative = []CompiledNegativeRule{negRule}

	// Create test risk scoring
	riskScoring := &config.RiskScoring{
		Base: map[string]string{
			"PII":       "medium",
			"PHI":       "high",
			"Financial": "high",
		},
		Combinations: map[string]string{
			"PHI+PII":           "high",
			"Financial+PII":     "critical",
			"Financial+PHI":     "critical",
			"Financial+PHI+PII": "critical",
		},
		Default: "low",
	}

	options := EnrichmentOptions{
		EmitUnknown: emitUnknown,
		Debug:       debug,
	}

	return NewEnricher(schema, dict, riskScoring, options)
}

func TestEnricher_ProcessEvent(t *testing.T) {
	tests := []struct {
		name        string
		event       map[string]interface{}
		emitUnknown bool
		debug       bool
		checkFunc   func(t *testing.T, result EnrichmentResult)
	}{
		{
			name: "pii_only_query",
			event: map[string]interface{}{
				"event_id":   "test-1",
				"db_system":  "postgres",
				"raw_query":  "SELECT ssn, email FROM patient WHERE patient_id = '123'",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Equal(t, []string{"PII"}, result.Categories)
				assert.Equal(t, "medium", result.RiskLevel)
				assert.Nil(t, result.Error)

				// Check sensitivity array
				sensitivity, exists := result.EnrichedEvent["sensitivity"].([]string)
				assert.True(t, exists)
				assert.Len(t, sensitivity, 2)
				assert.Contains(t, sensitivity, "PII:ssn")
				assert.Contains(t, sensitivity, "PII:email")

				// Check risk level
				assert.Equal(t, "medium", result.EnrichedEvent["risk_level"])

				// Should not have bulk flag
				_, hasBulk := result.EnrichedEvent["bulk"]
				assert.False(t, hasBulk)
			},
		},
		{
			name: "phi_only_query",
			event: map[string]interface{}{
				"event_id":   "test-2",
				"db_system":  "postgres",
				"raw_query":  "SELECT diagnosis, treatment FROM encounter WHERE patient_id = '123'",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Equal(t, []string{"PHI"}, result.Categories)
				assert.Equal(t, "high", result.RiskLevel)

				sensitivity, _ := result.EnrichedEvent["sensitivity"].([]string)
				assert.Len(t, sensitivity, 2)
				assert.Contains(t, sensitivity, "PHI:diagnosis")
				assert.Contains(t, sensitivity, "PHI:treatment")
			},
		},
		{
			name: "mixed_pii_phi_query",
			event: map[string]interface{}{
				"event_id":   "test-3",
				"db_system":  "postgres",
				"raw_query":  "SELECT p.ssn, e.diagnosis FROM patient p JOIN encounter e ON p.patient_id = e.patient_id",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Len(t, result.Categories, 2)
				assert.Contains(t, result.Categories, "PII")
				assert.Contains(t, result.Categories, "PHI")
				assert.Equal(t, "high", result.RiskLevel) // Combination rule

				sensitivity, _ := result.EnrichedEvent["sensitivity"].([]string)
				assert.Len(t, sensitivity, 2)
				assert.Contains(t, sensitivity, "PII:ssn")
				assert.Contains(t, sensitivity, "PHI:diagnosis")
			},
		},
		{
			name: "financial_query",
			event: map[string]interface{}{
				"event_id":   "test-4",
				"db_system":  "postgres",
				"raw_query":  "SELECT card_last4 FROM payment_method WHERE patient_id = '123'",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Equal(t, []string{"Financial"}, result.Categories)
				assert.Equal(t, "high", result.RiskLevel)

				sensitivity, _ := result.EnrichedEvent["sensitivity"].([]string)
				assert.Len(t, sensitivity, 1)
				assert.Contains(t, sensitivity, "Financial:card_last4")
			},
		},
		{
			name: "all_categories_critical",
			event: map[string]interface{}{
				"event_id":   "test-5",
				"db_system":  "postgres",
				"raw_query":  "SELECT p.ssn, e.diagnosis, pm.card_last4 FROM patient p JOIN encounter e ON p.patient_id = e.patient_id JOIN payment_method pm ON p.patient_id = pm.patient_id",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Len(t, result.Categories, 3)
				assert.Contains(t, result.Categories, "PII")
				assert.Contains(t, result.Categories, "PHI")
				assert.Contains(t, result.Categories, "Financial")
				assert.Equal(t, "critical", result.RiskLevel) // Triple combination

				sensitivity, _ := result.EnrichedEvent["sensitivity"].([]string)
				assert.Len(t, sensitivity, 3)
			},
		},
		{
			name: "bulk_operation",
			event: map[string]interface{}{
				"event_id":   "test-6",
				"db_system":  "postgres",
				"raw_query":  "SELECT * FROM patient",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)

				// Should detect bulk operation
				bulk, hasBulk := result.EnrichedEvent["bulk"].(bool)
				assert.True(t, hasBulk)
				assert.True(t, bulk)

				bulkType, hasBulkType := result.EnrichedEvent["bulk_type"].(string)
				assert.True(t, hasBulkType)
				assert.Equal(t, "select", bulkType)
			},
		},
		{
			name: "no_sensitive_data_emit_unknown_true",
			event: map[string]interface{}{
				"event_id":   "test-7",
				"db_system":  "postgres",
				"raw_query":  "SELECT first_name, last_name FROM patient",
				"query_type": "SELECT",
			},
			emitUnknown: true,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Empty(t, result.Categories)
				assert.Equal(t, "low", result.RiskLevel) // Default risk

				sensitivity, _ := result.EnrichedEvent["sensitivity"].([]string)
				assert.Empty(t, sensitivity)
				assert.Equal(t, "low", result.EnrichedEvent["risk_level"])
			},
		},
		{
			name: "no_sensitive_data_emit_unknown_false",
			event: map[string]interface{}{
				"event_id":   "test-8",
				"db_system":  "postgres",
				"raw_query":  "SELECT first_name, last_name FROM patient",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       false,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.False(t, result.ShouldEmit)
				assert.Empty(t, result.Categories)
				assert.Equal(t, "low", result.RiskLevel)
			},
		},
		{
			name: "debug_mode_enabled",
			event: map[string]interface{}{
				"event_id":   "test-9",
				"db_system":  "postgres",
				"raw_query":  "SELECT ssn FROM patient",
				"query_type": "SELECT",
			},
			emitUnknown: false,
			debug:       true,
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)

				// Should have debug info
				debugInfo, hasDebug := result.EnrichedEvent["debug_info"].(map[string]interface{})
				assert.True(t, hasDebug)
				assert.NotNil(t, debugInfo)

				// Check debug fields
				assert.Contains(t, debugInfo, "parsed_tables")
				assert.Contains(t, debugInfo, "parsed_columns")
				assert.Contains(t, debugInfo, "resolved_columns")
				assert.Contains(t, debugInfo, "matched_columns")
				assert.Contains(t, debugInfo, "category_matches")
				assert.Contains(t, debugInfo, "schema_status")

				schemaStatus, _ := debugInfo["schema_status"].(string)
				assert.Equal(t, "matched", schemaStatus)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enricher := createTestEnricher(tt.emitUnknown, tt.debug)
			result := enricher.ProcessEvent(tt.event)
			tt.checkFunc(t, result)
		})
	}
}

func TestEnricher_ProcessEventJSON(t *testing.T) {
	enricher := createTestEnricher(false, false)

	tests := []struct {
		name        string
		inputJSON   string
		expectEmit  bool
		expectError bool
		checkFunc   func(t *testing.T, outputJSON string)
	}{
		{
			name: "valid_pii_query",
			inputJSON: `{
				"event_id": "json-test-1",
				"db_system": "postgres",
				"raw_query": "SELECT ssn FROM patient WHERE patient_id = '123'",
				"query_type": "SELECT"
			}`,
			expectEmit:  true,
			expectError: false,
			checkFunc: func(t *testing.T, outputJSON string) {
				var event map[string]interface{}
				err := json.Unmarshal([]byte(outputJSON), &event)
				require.NoError(t, err)

				assert.Equal(t, "json-test-1", event["event_id"])
				assert.Equal(t, "medium", event["risk_level"])

				sensitivity, _ := event["sensitivity"].([]interface{})
				assert.Len(t, sensitivity, 1)
				assert.Equal(t, "PII:ssn", sensitivity[0])
			},
		},
		{
			name:        "invalid_json",
			inputJSON:   `{invalid json}`,
			expectEmit:  false,
			expectError: true,
		},
		{
			name: "no_sensitive_data",
			inputJSON: `{
				"event_id": "json-test-2",
				"db_system": "postgres",
				"raw_query": "SELECT first_name FROM patient",
				"query_type": "SELECT"
			}`,
			expectEmit:  false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputJSON, shouldEmit, err := enricher.ProcessEventJSON(tt.inputJSON)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectEmit, shouldEmit)

			if tt.expectEmit && tt.checkFunc != nil {
				tt.checkFunc(t, outputJSON)
			}
		})
	}
}

func TestEnricher_GetStats(t *testing.T) {
	enricher := createTestEnricher(true, true)
	stats := enricher.GetStats()

	// Check that all expected stats are present
	expectedKeys := []string{
		"schema_schemas", "dict_categories", "dict_negative_rules",
		"risk_base_rules", "risk_combinations",
		"emit_unknown", "debug_enabled", "dict_total_rules",
		"schema_tables", "schema_columns",
	}

	for _, key := range expectedKeys {
		assert.Contains(t, stats, key, "Missing stat key: %s", key)
	}

	// Check some specific values
	assert.Equal(t, 3, stats["schema_schemas"])  // healthcare, payments, public
	assert.Equal(t, 3, stats["dict_categories"]) // PII, PHI, Financial
	assert.Equal(t, 1, stats["dict_negative_rules"])
	assert.Equal(t, 3, stats["risk_base_rules"])
	assert.Equal(t, true, stats["emit_unknown"])
	assert.Equal(t, true, stats["debug_enabled"])
}

func TestEnricher_RealWorldScenarios(t *testing.T) {
	enricher := createTestEnricher(false, false)

	tests := []struct {
		name        string
		description string
		event       map[string]interface{}
		checkFunc   func(t *testing.T, result EnrichmentResult)
	}{
		{
			name:        "healthcare_patient_lookup",
			description: "Common healthcare query accessing patient PII",
			event: map[string]interface{}{
				"event_id":   "real-1",
				"db_system":  "postgres",
				"raw_query":  "SELECT patient_id, ssn, email FROM patient WHERE ssn = '123-45-6789'",
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Equal(t, []string{"PII"}, result.Categories)
				assert.Equal(t, "medium", result.RiskLevel)
			},
		},
		{
			name:        "medical_record_access",
			description: "Accessing both patient info and medical data",
			event: map[string]interface{}{
				"event_id":   "real-2",
				"db_system":  "postgres",
				"raw_query":  "SELECT p.ssn, p.email, e.diagnosis, e.treatment FROM patient p JOIN encounter e ON p.patient_id = e.patient_id WHERE p.patient_id = $1",
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Len(t, result.Categories, 2)
				assert.Contains(t, result.Categories, "PII")
				assert.Contains(t, result.Categories, "PHI")
				assert.Equal(t, "high", result.RiskLevel) // Combination rule
			},
		},
		{
			name:        "billing_query_critical",
			description: "Query accessing patient, medical, and payment data",
			event: map[string]interface{}{
				"event_id":   "real-3",
				"db_system":  "postgres",
				"raw_query":  "SELECT p.ssn, e.diagnosis, pm.card_last4 FROM patient p JOIN encounter e ON p.patient_id = e.patient_id JOIN payment_method pm ON p.patient_id = pm.patient_id WHERE e.encounter_id = $1",
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Len(t, result.Categories, 3)
				assert.Equal(t, "critical", result.RiskLevel) // Triple combination
			},
		},
		{
			name:        "bulk_patient_export",
			description: "Bulk export of patient data",
			event: map[string]interface{}{
				"event_id":   "real-4",
				"db_system":  "postgres",
				"raw_query":  "COPY (SELECT ssn, email FROM patient) TO '/tmp/patient_export.csv' WITH CSV",
				"query_type": "COPY",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.True(t, result.ShouldEmit)
				assert.Equal(t, []string{"PII"}, result.Categories)
				assert.Equal(t, "medium", result.RiskLevel)

				// Should be marked as bulk
				bulk, _ := result.EnrichedEvent["bulk"].(bool)
				assert.True(t, bulk)
				bulkType, _ := result.EnrichedEvent["bulk_type"].(string)
				assert.Equal(t, "export", bulkType)
			},
		},
		{
			name:        "system_query_no_sensitive_data",
			description: "System query with no sensitive data",
			event: map[string]interface{}{
				"event_id":   "real-5",
				"db_system":  "postgres",
				"raw_query":  "SELECT first_name, last_name FROM patient WHERE patient_id = $1",
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.False(t, result.ShouldEmit) // No sensitive data, emit_unknown=false
				assert.Empty(t, result.Categories)
				assert.Equal(t, "low", result.RiskLevel)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := enricher.ProcessEvent(tt.event)
			tt.checkFunc(t, result)
		})
	}
}

func TestEnricher_EdgeCases(t *testing.T) {
	enricher := createTestEnricher(false, false)

	tests := []struct {
		name      string
		event     map[string]interface{}
		checkFunc func(t *testing.T, result EnrichmentResult)
	}{
		{
			name: "empty_query",
			event: map[string]interface{}{
				"event_id":   "edge-1",
				"db_system":  "postgres",
				"raw_query":  "",
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.False(t, result.ShouldEmit)
				assert.Nil(t, result.Error)
			},
		},
		{
			name: "malformed_query",
			event: map[string]interface{}{
				"event_id":   "edge-2",
				"db_system":  "postgres",
				"raw_query":  "SELECTE * FORM patient", // Typos
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.False(t, result.ShouldEmit) // Parser should handle gracefully
				assert.Nil(t, result.Error)
			},
		},
		{
			name: "missing_fields",
			event: map[string]interface{}{
				"event_id": "edge-3",
				// Missing db_system, raw_query, query_type
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.False(t, result.ShouldEmit)
				assert.Nil(t, result.Error) // Should handle gracefully
			},
		},
		{
			name: "unknown_table",
			event: map[string]interface{}{
				"event_id":   "edge-4",
				"db_system":  "postgres",
				"raw_query":  "SELECT ssn FROM unknown_table",
				"query_type": "SELECT",
			},
			checkFunc: func(t *testing.T, result EnrichmentResult) {
				assert.False(t, result.ShouldEmit) // Can't resolve columns
				assert.Empty(t, result.Categories)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := enricher.ProcessEvent(tt.event)
			tt.checkFunc(t, result)
		})
	}
}

package enrich

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vaibhaw-/AuditR/internal/auditr/config"
)

func TestComputeRisk(t *testing.T) {
	// Create test risk scoring configuration
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

	tests := []struct {
		name       string
		categories []string
		expected   string
	}{
		{
			name:       "no_categories",
			categories: []string{},
			expected:   "low", // default
		},
		{
			name:       "single_pii",
			categories: []string{"PII"},
			expected:   "medium",
		},
		{
			name:       "single_phi",
			categories: []string{"PHI"},
			expected:   "high",
		},
		{
			name:       "single_financial",
			categories: []string{"Financial"},
			expected:   "high",
		},
		{
			name:       "single_unknown_category",
			categories: []string{"Unknown"},
			expected:   "low", // default when category not found
		},
		{
			name:       "pii_phi_combination",
			categories: []string{"PII", "PHI"},
			expected:   "high", // from combinations
		},
		{
			name:       "pii_financial_combination",
			categories: []string{"PII", "Financial"},
			expected:   "critical", // from combinations
		},
		{
			name:       "phi_financial_combination",
			categories: []string{"PHI", "Financial"},
			expected:   "critical", // from combinations
		},
		{
			name:       "all_three_combination",
			categories: []string{"PII", "PHI", "Financial"},
			expected:   "critical", // from combinations (Financial+PII+PHI)
		},
		{
			name:       "order_independence_pii_phi",
			categories: []string{"PHI", "PII"}, // Different order
			expected:   "high",                 // Should still find PII+PHI combination
		},
		{
			name:       "order_independence_all_three",
			categories: []string{"Financial", "PII", "PHI"}, // Different order
			expected:   "critical",                          // Should still find Financial+PII+PHI combination
		},
		{
			name:       "no_combination_found_use_max",
			categories: []string{"PII", "Unknown"}, // No combination exists
			expected:   "medium",                   // Max of PII (medium) and Unknown (not found, ignored)
		},
		{
			name:       "multiple_unknown_categories",
			categories: []string{"Unknown1", "Unknown2"},
			expected:   "low", // All unknown, use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeRisk(riskScoring, tt.categories)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateCombinationKey(t *testing.T) {
	tests := []struct {
		name       string
		categories []string
		expected   string
	}{
		{
			name:       "empty_categories",
			categories: []string{},
			expected:   "",
		},
		{
			name:       "single_category",
			categories: []string{"PII"},
			expected:   "PII",
		},
		{
			name:       "two_categories_alphabetical",
			categories: []string{"Financial", "PII"},
			expected:   "Financial+PII",
		},
		{
			name:       "two_categories_reverse_order",
			categories: []string{"PII", "Financial"},
			expected:   "Financial+PII", // Should be sorted
		},
		{
			name:       "three_categories_mixed_order",
			categories: []string{"PHI", "Financial", "PII"},
			expected:   "Financial+PHI+PII", // Should be sorted alphabetically
		},
		{
			name:       "duplicate_categories",
			categories: []string{"PII", "PII", "Financial"},
			expected:   "Financial+PII+PII", // Duplicates preserved but sorted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createCombinationKey(tt.categories)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetMaximumBaseRisk(t *testing.T) {
	riskScoring := &config.RiskScoring{
		Base: map[string]string{
			"PII":       "medium",
			"PHI":       "high",
			"Financial": "high",
			"Low":       "low",
		},
		Default: "low",
	}

	tests := []struct {
		name       string
		categories []string
		expected   string
	}{
		{
			name:       "single_low_risk",
			categories: []string{"Low"},
			expected:   "low",
		},
		{
			name:       "single_medium_risk",
			categories: []string{"PII"},
			expected:   "medium",
		},
		{
			name:       "single_high_risk",
			categories: []string{"PHI"},
			expected:   "high",
		},
		{
			name:       "medium_and_high",
			categories: []string{"PII", "PHI"},
			expected:   "high", // Max of medium and high
		},
		{
			name:       "low_medium_high",
			categories: []string{"Low", "PII", "PHI"},
			expected:   "high", // Max of low, medium, and high
		},
		{
			name:       "all_same_level",
			categories: []string{"PHI", "Financial"},
			expected:   "high", // Both are high, return high
		},
		{
			name:       "unknown_categories",
			categories: []string{"Unknown1", "Unknown2"},
			expected:   "low", // No valid categories, use default
		},
		{
			name:       "mixed_known_unknown",
			categories: []string{"PII", "Unknown", "PHI"},
			expected:   "high", // Max of known categories (medium, high) = high
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMaximumBaseRisk(riskScoring, tt.categories)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateRiskLevel(t *testing.T) {
	tests := []struct {
		riskLevel string
		expected  bool
	}{
		{"low", true},
		{"medium", true},
		{"high", true},
		{"critical", true},
		{"invalid", false},
		{"", false},
		{"LOW", false},    // Case sensitive
		{"Medium", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.riskLevel, func(t *testing.T) {
			result := ValidateRiskLevel(tt.riskLevel)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompareRiskLevels(t *testing.T) {
	tests := []struct {
		name     string
		level1   string
		level2   string
		expected int
	}{
		// Equal comparisons
		{"low_equals_low", "low", "low", 0},
		{"medium_equals_medium", "medium", "medium", 0},
		{"high_equals_high", "high", "high", 0},
		{"critical_equals_critical", "critical", "critical", 0},

		// Less than comparisons
		{"low_less_than_medium", "low", "medium", -1},
		{"low_less_than_high", "low", "high", -1},
		{"low_less_than_critical", "low", "critical", -1},
		{"medium_less_than_high", "medium", "high", -1},
		{"medium_less_than_critical", "medium", "critical", -1},
		{"high_less_than_critical", "high", "critical", -1},

		// Greater than comparisons
		{"medium_greater_than_low", "medium", "low", 1},
		{"high_greater_than_low", "high", "low", 1},
		{"critical_greater_than_low", "critical", "low", 1},
		{"high_greater_than_medium", "high", "medium", 1},
		{"critical_greater_than_medium", "critical", "medium", 1},
		{"critical_greater_than_high", "critical", "high", 1},

		// Invalid comparisons
		{"invalid_level1", "invalid", "low", 0},
		{"invalid_level2", "low", "invalid", 0},
		{"both_invalid", "invalid1", "invalid2", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareRiskLevels(tt.level1, tt.level2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRiskLevelValue(t *testing.T) {
	tests := []struct {
		riskLevel string
		expected  int
	}{
		{"low", 1},
		{"medium", 2},
		{"high", 3},
		{"critical", 4},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.riskLevel, func(t *testing.T) {
			result := GetRiskLevelValue(tt.riskLevel)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestComputeRisk_RealWorldScenarios(t *testing.T) {
	// Use the actual risk scoring from the project
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

	tests := []struct {
		name        string
		description string
		categories  []string
		expected    string
	}{
		{
			name:        "healthcare_patient_query",
			description: "Query accessing patient SSN and email (PII only)",
			categories:  []string{"PII"},
			expected:    "medium",
		},
		{
			name:        "medical_diagnosis_query",
			description: "Query accessing diagnosis information (PHI only)",
			categories:  []string{"PHI"},
			expected:    "high",
		},
		{
			name:        "payment_processing_query",
			description: "Query accessing card information (Financial only)",
			categories:  []string{"Financial"},
			expected:    "high",
		},
		{
			name:        "patient_medical_record",
			description: "Query accessing both patient info and medical data",
			categories:  []string{"PII", "PHI"},
			expected:    "high", // Combination rule
		},
		{
			name:        "billing_with_patient_info",
			description: "Query accessing patient info and payment data",
			categories:  []string{"PII", "Financial"},
			expected:    "critical", // Combination rule
		},
		{
			name:        "medical_billing_query",
			description: "Query accessing medical and payment data",
			categories:  []string{"PHI", "Financial"},
			expected:    "critical", // Combination rule
		},
		{
			name:        "comprehensive_patient_record",
			description: "Query accessing all sensitive data types",
			categories:  []string{"PII", "PHI", "Financial"},
			expected:    "critical", // Combination rule
		},
		{
			name:        "system_metadata_query",
			description: "Query accessing only non-sensitive system data",
			categories:  []string{},
			expected:    "low", // Default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeRisk(riskScoring, tt.categories)
			assert.Equal(t, tt.expected, result, "Scenario: %s", tt.description)
		})
	}
}

func TestComputeRisk_EdgeCases(t *testing.T) {
	riskScoring := &config.RiskScoring{
		Base: map[string]string{
			"PII": "medium",
		},
		Combinations: map[string]string{
			"PII+Unknown": "high", // This combination shouldn't match due to unknown category
		},
		Default: "low",
	}

	tests := []struct {
		name       string
		categories []string
		expected   string
	}{
		{
			name:       "nil_categories",
			categories: nil,
			expected:   "low", // Should handle nil as empty
		},
		{
			name:       "combination_with_unknown_category",
			categories: []string{"PII", "Unknown"},
			expected:   "high", // Combination "PII+Unknown" exists in test config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeRisk(riskScoring, tt.categories)
			assert.Equal(t, tt.expected, result)
		})
	}
}

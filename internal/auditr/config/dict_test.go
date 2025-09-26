package config

import (
	"strings"
	"testing"
)

func TestValidateDictAndRiskScoring(t *testing.T) {
	validDict := `{
		"PII": [
			{ "regex": "(?i)^ssn$", "expected_types": ["VARCHAR"] }
		],
		"PHI": [
			{ "regex": "(?i)^dob$", "expected_types": ["DATE"] }
		],
		"Negative": [
			{ "regex": "tmp_", "reason": "ignore temp tables" }
		]
	}`

	validRisk := `{
		"base": {
			"PII": "medium",
			"PHI": "high"
		},
		"combinations": {
			"PII+PHI": "critical"
		},
		"default": "low"
	}`

	dict, cats, err := ValidateDict(strings.NewReader(validDict))
	if err != nil {
		t.Fatalf("dict validation failed: %v", err)
	}
	if len(dict.Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(dict.Categories))
	}
	if len(dict.Negative) != 1 {
		t.Errorf("expected 1 negative rule, got %d", len(dict.Negative))
	}

	_, err = ValidateRiskScoring(strings.NewReader(validRisk), cats)
	if err != nil {
		t.Fatalf("risk validation failed: %v", err)
	}
}

func TestInvalidRiskScoringMissingCategory(t *testing.T) {
	dict := `{"PII":[{"regex":"x","expected_types":["VARCHAR"]}]}`
	risk := `{"base":{"PHI":"high"},"default":"low"}`

	_, cats, _ := ValidateDict(strings.NewReader(dict))
	_, err := ValidateRiskScoring(strings.NewReader(risk), cats)
	if err == nil {
		t.Errorf("expected error for missing category in risk scoring")
	}
}

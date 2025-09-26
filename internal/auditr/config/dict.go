package config

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// PositiveRule = rule in sensitivity categories like PII/PHI/Financial
type PositiveRule struct {
	Regex         string   `json:"regex"`
	ExpectedTypes []string `json:"expected_types"`
	SamplePattern string   `json:"sample_pattern,omitempty"`
}

// NegativeRule = exclusion rule
type NegativeRule struct {
	Regex  string `json:"regex"`
	Reason string `json:"reason"`
}

// SensitivityDict = the full dictionary
// Categories = PII, PHI, Financial, etc.
type SensitivityDict struct {
	Categories map[string][]PositiveRule
	Negative   []NegativeRule
}

// RiskScoring model
type RiskScoring struct {
	Base         map[string]string `json:"base"`
	Combinations map[string]string `json:"combinations"`
	Default      string            `json:"default"`
}

// Allowed risk levels
var allowedRisks = map[string]struct{}{
	"low": {}, "medium": {}, "high": {}, "critical": {},
}

// ValidateDict validates the sensitivity dictionary JSON
func ValidateDict(r io.Reader) (*SensitivityDict, []string, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("failed to decode dict JSON: %w", err)
	}

	dict := &SensitivityDict{Categories: map[string][]PositiveRule{}}
	var categories []string

	for category, msg := range raw {
		if category == "Negative" {
			var rules []NegativeRule
			if err := json.Unmarshal(msg, &rules); err != nil {
				return nil, nil, fmt.Errorf("decode Negative rules: %w", err)
			}
			if len(rules) == 0 {
				return nil, nil, fmt.Errorf("Negative category must not be empty")
			}
			for i, rule := range rules {
				if rule.Regex == "" {
					return nil, nil, fmt.Errorf("Negative rule %d missing regex", i)
				}
				if _, err := regexp.Compile(rule.Regex); err != nil {
					return nil, nil, fmt.Errorf("Negative rule %d invalid regex: %w", i, err)
				}
				if rule.Reason == "" {
					return nil, nil, fmt.Errorf("Negative rule %d missing reason", i)
				}
			}
			dict.Negative = rules
		} else {
			var rules []PositiveRule
			if err := json.Unmarshal(msg, &rules); err != nil {
				return nil, nil, fmt.Errorf("decode %s rules: %w", category, err)
			}
			if len(rules) == 0 {
				return nil, nil, fmt.Errorf("category %q must not be empty", category)
			}
			for i, rule := range rules {
				if rule.Regex == "" {
					return nil, nil, fmt.Errorf("rule %d in %q missing regex", i, category)
				}
				if _, err := regexp.Compile(rule.Regex); err != nil {
					return nil, nil, fmt.Errorf("rule %d in %q invalid regex: %w", i, category, err)
				}
				if len(rule.ExpectedTypes) == 0 {
					return nil, nil, fmt.Errorf("rule %d in %q missing expected_types", i, category)
				}
			}
			dict.Categories[category] = rules
			categories = append(categories, category)
		}
	}

	if len(dict.Categories) == 0 {
		return nil, nil, fmt.Errorf("no sensitivity categories found")
	}

	return dict, categories, nil
}

// ValidateRiskScoring validates risk_scoring.json and cross-checks with dict categories
func ValidateRiskScoring(r io.Reader, categories []string) (*RiskScoring, error) {
	var rs RiskScoring
	if err := json.NewDecoder(r).Decode(&rs); err != nil {
		return nil, fmt.Errorf("failed to decode risk scoring JSON: %w", err)
	}

	if len(rs.Base) == 0 {
		return nil, fmt.Errorf("risk scoring 'base' must not be empty")
	}
	if rs.Default == "" {
		return nil, fmt.Errorf("risk scoring must define a default risk level")
	}

	// validate risk levels
	checkRisk := func(level, context string) error {
		if _, ok := allowedRisks[level]; !ok {
			return fmt.Errorf("invalid risk level %q in %s", level, context)
		}
		return nil
	}
	for cat, risk := range rs.Base {
		if err := checkRisk(risk, fmt.Sprintf("base[%s]", cat)); err != nil {
			return nil, err
		}
	}
	for comb, risk := range rs.Combinations {
		if err := checkRisk(risk, fmt.Sprintf("combinations[%s]", comb)); err != nil {
			return nil, err
		}
	}
	if err := checkRisk(rs.Default, "default"); err != nil {
		return nil, err
	}

	// cross-validate categories
	for _, cat := range categories {
		if _, ok := rs.Base[cat]; !ok {
			return nil, fmt.Errorf("risk scoring missing category %q", cat)
		}
	}

	return &rs, nil
}

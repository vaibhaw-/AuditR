package enrich

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// CompiledRule represents a sensitivity rule with compiled regex for efficient matching
type CompiledRule struct {
	// Original rule data
	Regex         string   `json:"regex"`
	ExpectedTypes []string `json:"expected_types"`
	SamplePattern string   `json:"sample_pattern,omitempty"`

	// Compiled regex for efficient matching
	CompiledRegex *regexp.Regexp `json:"-"`
}

// CompiledNegativeRule represents a negative (exclusion) rule with compiled regex
type CompiledNegativeRule struct {
	Regex  string `json:"regex"`
	Reason string `json:"reason"`

	// Compiled regex for efficient matching
	CompiledRegex *regexp.Regexp `json:"-"`
}

// CompiledSensitivityDict represents the sensitivity dictionary with compiled regexes
type CompiledSensitivityDict struct {
	// Categories maps category names (PII, PHI, Financial) to their rules
	Categories map[string][]CompiledRule

	// Negative rules for exclusions
	Negative []CompiledNegativeRule

	// CategoryNames provides a sorted list of category names for consistent processing
	CategoryNames []string
}

// LoadDict loads and validates the sensitivity dictionary from a file path.
// It uses the existing config.ValidateDict function and compiles all regexes for efficient matching.
func LoadDict(path string) (*CompiledSensitivityDict, error) {
	logger.L().Debugw("Loading sensitivity dictionary", "path", path)

	// Open and read the dictionary file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open dictionary file %s: %w", path, err)
	}
	defer file.Close()

	// Use the existing validation function from config package
	dict, categoryNames, err := config.ValidateDict(file)
	if err != nil {
		return nil, fmt.Errorf("failed to validate dictionary: %w", err)
	}

	logger.L().Debugw("Dictionary validation successful",
		"categories", len(categoryNames),
		"category_names", strings.Join(categoryNames, ","))

	// Create compiled dictionary
	compiledDict := &CompiledSensitivityDict{
		Categories:    make(map[string][]CompiledRule),
		CategoryNames: categoryNames,
	}

	// Compile positive rules for each category
	totalRules := 0
	for categoryName, rules := range dict.Categories {
		var compiledRules []CompiledRule

		for i, rule := range rules {
			// Compile the regex
			compiledRegex, err := regexp.Compile(rule.Regex)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex for category %s, rule %d (%s): %w",
					categoryName, i, rule.Regex, err)
			}

			compiledRule := CompiledRule{
				Regex:         rule.Regex,
				ExpectedTypes: rule.ExpectedTypes,
				SamplePattern: rule.SamplePattern,
				CompiledRegex: compiledRegex,
			}

			compiledRules = append(compiledRules, compiledRule)
			totalRules++

			logger.L().Debugw("Compiled sensitivity rule",
				"category", categoryName,
				"regex", rule.Regex,
				"expected_types", strings.Join(rule.ExpectedTypes, ","))
		}

		compiledDict.Categories[categoryName] = compiledRules
	}

	// Compile negative rules
	for i, negRule := range dict.Negative {
		compiledRegex, err := regexp.Compile(negRule.Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile negative rule regex %d (%s): %w",
				i, negRule.Regex, err)
		}

		compiledNegRule := CompiledNegativeRule{
			Regex:         negRule.Regex,
			Reason:        negRule.Reason,
			CompiledRegex: compiledRegex,
		}

		compiledDict.Negative = append(compiledDict.Negative, compiledNegRule)

		logger.L().Debugw("Compiled negative rule",
			"regex", negRule.Regex,
			"reason", negRule.Reason)
	}

	logger.L().Debugw("Dictionary compilation completed",
		"total_positive_rules", totalRules,
		"negative_rules", len(compiledDict.Negative),
		"categories", strings.Join(categoryNames, ","))

	return compiledDict, nil
}

// LoadRisk loads and validates the risk scoring configuration from a file path.
// It uses the existing config.ValidateRiskScoring function.
func LoadRisk(path string, categoryNames []string) (*config.RiskScoring, error) {
	logger.L().Debugw("Loading risk scoring configuration", "path", path)

	// Open and read the risk scoring file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open risk scoring file %s: %w", path, err)
	}
	defer file.Close()

	// Use the existing validation function from config package
	riskScoring, err := config.ValidateRiskScoring(file, categoryNames)
	if err != nil {
		return nil, fmt.Errorf("failed to validate risk scoring: %w", err)
	}

	logger.L().Debugw("Risk scoring validation successful",
		"base_categories", len(riskScoring.Base),
		"combinations", len(riskScoring.Combinations),
		"default_risk", riskScoring.Default)

	// Log the loaded risk mappings for debugging
	for category, risk := range riskScoring.Base {
		logger.L().Debugw("Base risk mapping",
			"category", category,
			"risk_level", risk)
	}

	for combo, risk := range riskScoring.Combinations {
		logger.L().Debugw("Combination risk mapping",
			"combination", combo,
			"risk_level", risk)
	}

	return riskScoring, nil
}

// MatchColumn checks if a column name matches any sensitivity rules for a given category.
// It returns true if the column matches and the column type is in the expected types.
func (cd *CompiledSensitivityDict) MatchColumn(categoryName, columnName, columnType string) bool {
	rules, exists := cd.Categories[categoryName]
	if !exists {
		return false
	}

	for _, rule := range rules {
		// Check if the column name matches the regex
		if rule.CompiledRegex.MatchString(columnName) {
			// Check if the column type is in the expected types (if specified)
			if len(rule.ExpectedTypes) == 0 {
				// No type restriction, match is valid
				return true
			}

			// Check if the normalized column type matches any expected type
			for _, expectedType := range rule.ExpectedTypes {
				if columnType == expectedType {
					return true
				}
			}
		}
	}

	return false
}

// IsNegativeMatch checks if a column name matches any negative (exclusion) rules.
// Returns true if the column should be excluded, along with the exclusion reason.
func (cd *CompiledSensitivityDict) IsNegativeMatch(columnName string) (bool, string) {
	for _, negRule := range cd.Negative {
		if negRule.CompiledRegex.MatchString(columnName) {
			return true, negRule.Reason
		}
	}
	return false, ""
}

// FindMatches finds all sensitivity categories that match a given column.
// It returns a map of category names to the specific rules that matched.
// Negative rules are applied to exclude matches.
func (cd *CompiledSensitivityDict) FindMatches(columnName, columnType string) map[string][]CompiledRule {
	matches := make(map[string][]CompiledRule)

	// First check if this column should be excluded by negative rules
	if isNegative, reason := cd.IsNegativeMatch(columnName); isNegative {
		logger.L().Debugw("Column excluded by negative rule",
			"column", columnName,
			"reason", reason)
		return matches // Return empty matches
	}

	// Check each category for matches
	for _, categoryName := range cd.CategoryNames {
		rules := cd.Categories[categoryName]

		for _, rule := range rules {
			// Check if the column name matches the regex
			if rule.CompiledRegex.MatchString(columnName) {
				// Check if the column type is in the expected types (if specified)
				typeMatches := len(rule.ExpectedTypes) == 0 // No type restriction means match

				if !typeMatches {
					for _, expectedType := range rule.ExpectedTypes {
						if columnType == expectedType {
							typeMatches = true
							break
						}
					}
				}

				if typeMatches {
					matches[categoryName] = append(matches[categoryName], rule)
					logger.L().Debugw("Column matched sensitivity rule",
						"column", columnName,
						"type", columnType,
						"category", categoryName,
						"regex", rule.Regex)
				} else {
					logger.L().Debugw("Column name matched but type didn't",
						"column", columnName,
						"actual_type", columnType,
						"category", categoryName,
						"regex", rule.Regex,
						"expected_types", strings.Join(rule.ExpectedTypes, ","))
				}
			}
		}
	}

	return matches
}

// GetCategoryNames returns the list of category names in the dictionary.
func (cd *CompiledSensitivityDict) GetCategoryNames() []string {
	return cd.CategoryNames
}

package enrich

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDict(t *testing.T) {
	tests := []struct {
		name        string
		dictContent string
		expectError bool
		checkFunc   func(t *testing.T, dict *CompiledSensitivityDict)
	}{
		{
			name: "valid_dictionary",
			dictContent: `{
				"PII": [
					{
						"regex": "(?i)^ssn$",
						"expected_types": ["VARCHAR", "CHAR", "TEXT"],
						"sample_pattern": "^\\d{3}-\\d{2}-\\d{4}$"
					},
					{
						"regex": "(?i)^email$",
						"expected_types": ["VARCHAR", "TEXT"]
					}
				],
				"PHI": [
					{
						"regex": "(?i)^diagnosis$",
						"expected_types": ["TEXT"]
					}
				],
				"Negative": [
					{
						"regex": "(?i)^system_state$",
						"reason": "Operational state, not PII"
					}
				]
			}`,
			expectError: false,
			checkFunc: func(t *testing.T, dict *CompiledSensitivityDict) {
				// Check categories
				assert.Len(t, dict.Categories, 2)
				assert.Contains(t, dict.Categories, "PII")
				assert.Contains(t, dict.Categories, "PHI")

				// Check PII rules
				piiRules := dict.Categories["PII"]
				assert.Len(t, piiRules, 2)

				// Check that regexes are compiled
				assert.NotNil(t, piiRules[0].CompiledRegex)
				assert.NotNil(t, piiRules[1].CompiledRegex)

				// Check negative rules
				assert.Len(t, dict.Negative, 1)
				assert.NotNil(t, dict.Negative[0].CompiledRegex)

				// Check category names
				assert.Len(t, dict.CategoryNames, 2)
				assert.Contains(t, dict.CategoryNames, "PII")
				assert.Contains(t, dict.CategoryNames, "PHI")
			},
		},
		{
			name: "invalid_regex",
			dictContent: `{
				"PII": [
					{
						"regex": "[invalid regex",
						"expected_types": ["VARCHAR"]
					}
				]
			}`,
			expectError: true,
		},
		{
			name:        "empty_dictionary",
			dictContent: `{}`,
			expectError: true, // Empty dictionaries are not allowed by validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary dictionary file
			tmpFile, err := os.CreateTemp("", "dict_test_*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.dictContent)
			require.NoError(t, err)
			tmpFile.Close()

			// Test the function
			result, err := LoadDict(tmpFile.Name())

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestLoadDict_RealFile(t *testing.T) {
	// Test with the actual sensitivity dictionary from the project
	dictPath := filepath.Join("..", "..", "..", "cmd", "auditr", "config", "sensitivity_dict_extended.json")

	// Check if file exists, skip test if not found
	if _, err := os.Stat(dictPath); os.IsNotExist(err) {
		t.Skipf("Dictionary file not found: %s", dictPath)
	}

	dict, err := LoadDict(dictPath)
	require.NoError(t, err)
	require.NotNil(t, dict)

	// Check that expected categories exist
	expectedCategories := []string{"PII", "PHI", "Financial"}
	for _, category := range expectedCategories {
		assert.Contains(t, dict.Categories, category, "Expected category %s not found", category)
		assert.NotEmpty(t, dict.Categories[category], "Category %s has no rules", category)
	}

	// Check that all regexes are compiled
	for categoryName, rules := range dict.Categories {
		for i, rule := range rules {
			assert.NotNil(t, rule.CompiledRegex,
				"Regex not compiled for category %s, rule %d", categoryName, i)
		}
	}

	// Check negative rules
	for i, negRule := range dict.Negative {
		assert.NotNil(t, negRule.CompiledRegex,
			"Negative regex not compiled for rule %d", i)
	}

	// Test some specific matches
	t.Run("test_specific_matches", func(t *testing.T) {
		// Test SSN matching
		assert.True(t, dict.MatchColumn("PII", "ssn", "VARCHAR"))
		assert.True(t, dict.MatchColumn("PII", "SSN", "CHAR")) // Case insensitive
		assert.False(t, dict.MatchColumn("PII", "ssn", "INT")) // Wrong type

		// Test email matching
		assert.True(t, dict.MatchColumn("PII", "email", "VARCHAR"))
		assert.True(t, dict.MatchColumn("PII", "email", "TEXT"))

		// Test diagnosis matching (PHI)
		assert.True(t, dict.MatchColumn("PHI", "diagnosis", "TEXT"))

		// Test card_last4 matching (Financial)
		assert.True(t, dict.MatchColumn("Financial", "card_last4", "CHAR"))
	})
}

func TestLoadRisk(t *testing.T) {
	tests := []struct {
		name          string
		riskContent   string
		categoryNames []string
		expectError   bool
		checkFunc     func(t *testing.T, risk interface{})
	}{
		{
			name: "valid_risk_scoring",
			riskContent: `{
				"base": {
					"PII": "medium",
					"PHI": "high",
					"Financial": "high"
				},
				"combinations": {
					"PII+PHI": "high",
					"PII+Financial": "critical"
				},
				"default": "low"
			}`,
			categoryNames: []string{"PII", "PHI", "Financial"},
			expectError:   false,
			checkFunc: func(t *testing.T, risk interface{}) {
				// Type assertion would be done here
				// For now, just check it's not nil
				assert.NotNil(t, risk)
			},
		},
		{
			name: "invalid_risk_level",
			riskContent: `{
				"base": {
					"PII": "invalid_level"
				},
				"default": "low"
			}`,
			categoryNames: []string{"PII"},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary risk file
			tmpFile, err := os.CreateTemp("", "risk_test_*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.riskContent)
			require.NoError(t, err)
			tmpFile.Close()

			// Test the function
			result, err := LoadRisk(tmpFile.Name(), tt.categoryNames)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestLoadRisk_RealFile(t *testing.T) {
	// Test with the actual risk scoring file from the project
	riskPath := filepath.Join("..", "..", "..", "cmd", "auditr", "config", "risk_scoring.json")

	// Check if file exists, skip test if not found
	if _, err := os.Stat(riskPath); os.IsNotExist(err) {
		t.Skipf("Risk scoring file not found: %s", riskPath)
	}

	categoryNames := []string{"PII", "PHI", "Financial"}
	risk, err := LoadRisk(riskPath, categoryNames)
	require.NoError(t, err)
	require.NotNil(t, risk)

	// Check base mappings
	assert.Contains(t, risk.Base, "PII")
	assert.Contains(t, risk.Base, "PHI")
	assert.Contains(t, risk.Base, "Financial")

	// Check that risk levels are valid
	validLevels := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

	for category, level := range risk.Base {
		assert.True(t, validLevels[level],
			"Invalid risk level %s for category %s", level, category)
	}

	for combo, level := range risk.Combinations {
		assert.True(t, validLevels[level],
			"Invalid risk level %s for combination %s", level, combo)
	}

	assert.True(t, validLevels[risk.Default],
		"Invalid default risk level %s", risk.Default)
}

func TestCompiledSensitivityDict_MatchColumn(t *testing.T) {
	// Create a test dictionary
	dict := &CompiledSensitivityDict{
		Categories:    make(map[string][]CompiledRule),
		CategoryNames: []string{"PII", "PHI"},
	}

	// Add some test rules (we'll compile them manually for testing)
	ssnRule := CompiledRule{
		Regex:         "(?i)^ssn$",
		ExpectedTypes: []string{"VARCHAR", "CHAR"},
	}
	ssnRule.CompiledRegex = regexp.MustCompile(ssnRule.Regex)

	emailRule := CompiledRule{
		Regex:         "(?i)^email$",
		ExpectedTypes: []string{"VARCHAR", "TEXT"},
	}
	emailRule.CompiledRegex = regexp.MustCompile(emailRule.Regex)

	diagnosisRule := CompiledRule{
		Regex:         "(?i)^diagnosis$",
		ExpectedTypes: []string{"TEXT"},
	}
	diagnosisRule.CompiledRegex = regexp.MustCompile(diagnosisRule.Regex)

	dict.Categories["PII"] = []CompiledRule{ssnRule, emailRule}
	dict.Categories["PHI"] = []CompiledRule{diagnosisRule}

	tests := []struct {
		category   string
		columnName string
		columnType string
		expected   bool
	}{
		// Positive matches
		{"PII", "ssn", "VARCHAR", true},
		{"PII", "SSN", "CHAR", true}, // Case insensitive
		{"PII", "email", "TEXT", true},
		{"PHI", "diagnosis", "TEXT", true},

		// Negative matches - wrong type
		{"PII", "ssn", "INT", false},
		{"PII", "email", "INT", false},
		{"PHI", "diagnosis", "VARCHAR", false},

		// Negative matches - wrong column name
		{"PII", "password", "VARCHAR", false},
		{"PHI", "treatment", "TEXT", false},

		// Negative matches - wrong category
		{"Financial", "ssn", "VARCHAR", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s_%s", tt.category, tt.columnName, tt.columnType), func(t *testing.T) {
			result := dict.MatchColumn(tt.category, tt.columnName, tt.columnType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompiledSensitivityDict_IsNegativeMatch(t *testing.T) {
	dict := &CompiledSensitivityDict{}

	// Add negative rule
	negRule := CompiledNegativeRule{
		Regex:  "(?i)^system_state$",
		Reason: "Operational state, not PII",
	}
	negRule.CompiledRegex = regexp.MustCompile(negRule.Regex)
	dict.Negative = []CompiledNegativeRule{negRule}

	tests := []struct {
		columnName     string
		expectedMatch  bool
		expectedReason string
	}{
		{"system_state", true, "Operational state, not PII"},
		{"SYSTEM_STATE", true, "Operational state, not PII"}, // Case insensitive
		{"user_state", false, ""},
		{"ssn", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.columnName, func(t *testing.T) {
			isMatch, reason := dict.IsNegativeMatch(tt.columnName)
			assert.Equal(t, tt.expectedMatch, isMatch)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestCompiledSensitivityDict_FindMatches(t *testing.T) {
	// Create a comprehensive test dictionary
	dict := &CompiledSensitivityDict{
		Categories:    make(map[string][]CompiledRule),
		CategoryNames: []string{"PII", "Financial"},
	}

	// Add PII rules
	ssnRule := CompiledRule{
		Regex:         "(?i)^ssn$",
		ExpectedTypes: []string{"VARCHAR", "CHAR"},
	}
	ssnRule.CompiledRegex = regexp.MustCompile(ssnRule.Regex)

	// Add Financial rules
	cardRule := CompiledRule{
		Regex:         "(?i)^card_last4$",
		ExpectedTypes: []string{"CHAR"},
	}
	cardRule.CompiledRegex = regexp.MustCompile(cardRule.Regex)

	dict.Categories["PII"] = []CompiledRule{ssnRule}
	dict.Categories["Financial"] = []CompiledRule{cardRule}

	// Add negative rule
	negRule := CompiledNegativeRule{
		Regex:  "(?i)^system_",
		Reason: "System fields",
	}
	negRule.CompiledRegex = regexp.MustCompile(negRule.Regex)
	dict.Negative = []CompiledNegativeRule{negRule}

	tests := []struct {
		name               string
		columnName         string
		columnType         string
		expectedCount      int
		expectedCategories []string
	}{
		{
			name:               "ssn_match",
			columnName:         "ssn",
			columnType:         "VARCHAR",
			expectedCount:      1,
			expectedCategories: []string{"PII"},
		},
		{
			name:               "card_match",
			columnName:         "card_last4",
			columnType:         "CHAR",
			expectedCount:      1,
			expectedCategories: []string{"Financial"},
		},
		{
			name:               "no_match_wrong_type",
			columnName:         "ssn",
			columnType:         "INT",
			expectedCount:      0,
			expectedCategories: []string{},
		},
		{
			name:               "no_match_negative_rule",
			columnName:         "system_id",
			columnType:         "VARCHAR",
			expectedCount:      0,
			expectedCategories: []string{},
		},
		{
			name:               "no_match_unknown_column",
			columnName:         "unknown_column",
			columnType:         "VARCHAR",
			expectedCount:      0,
			expectedCategories: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := dict.FindMatches(tt.columnName, tt.columnType)
			assert.Len(t, matches, tt.expectedCount)

			for _, expectedCategory := range tt.expectedCategories {
				assert.Contains(t, matches, expectedCategory)
				assert.NotEmpty(t, matches[expectedCategory])
			}
		})
	}
}

func TestLoadDict_FileNotFound(t *testing.T) {
	_, err := LoadDict("/nonexistent/path/dict.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open dictionary file")
}

func TestLoadRisk_FileNotFound(t *testing.T) {
	_, err := LoadRisk("/nonexistent/path/risk.json", []string{"PII"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open risk scoring file")
}

package enrich

import (
	"sort"
	"strings"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

// ComputeRisk calculates the risk level for a given set of sensitivity categories
// using the provided risk scoring configuration.
//
// Logic:
// - If no categories: return default risk level
// - If single category: return base risk level for that category
// - If multiple categories: look for combination in combinations map, otherwise return max base risk
// - Categories are sorted alphabetically before combination lookup for consistency
//
// Risk level hierarchy (lowest to highest): low < medium < high < critical
func ComputeRisk(riskScoring *config.RiskScoring, categories []string) string {
	logger.L().Debugw("Computing risk level",
		"categories", strings.Join(categories, ","),
		"risk_config", riskScoring)

	// Handle empty categories
	if len(categories) == 0 {
		logger.L().Debugw("No categories found, using default risk",
			"default_risk", riskScoring.Default)
		return riskScoring.Default
	}

	// Handle single category
	if len(categories) == 1 {
		category := categories[0]
		if baseRisk, exists := riskScoring.Base[category]; exists {
			logger.L().Debugw("Single category found, using base risk",
				"category", category,
				"base_risk", baseRisk)
			return baseRisk
		}

		// Category not found in base mapping, use default
		logger.L().Warnw("Category not found in base risk mapping, using default",
			"category", category,
			"default_risk", riskScoring.Default)
		return riskScoring.Default
	}

	// Handle multiple categories
	// First, try to find a combination mapping
	combinationKey := createCombinationKey(categories)
	if combinationRisk, exists := riskScoring.Combinations[combinationKey]; exists {
		logger.L().Debugw("Found combination risk mapping",
			"combination_key", combinationKey,
			"combination_risk", combinationRisk)
		return combinationRisk
	}

	// No combination found, use the maximum base risk level
	maxRisk := getMaximumBaseRisk(riskScoring, categories)
	logger.L().Debugw("No combination found, using maximum base risk",
		"categories", strings.Join(categories, ","),
		"max_risk", maxRisk)

	return maxRisk
}

// createCombinationKey creates a sorted, plus-separated key for category combinations
// e.g., ["Financial", "PII"] -> "Financial+PII"
// e.g., ["PHI", "PII", "Financial"] -> "Financial+PHI+PII"
func createCombinationKey(categories []string) string {
	if len(categories) == 0 {
		return ""
	}

	// Create a copy to avoid modifying the original slice
	sortedCategories := make([]string, len(categories))
	copy(sortedCategories, categories)

	// Sort alphabetically for consistent key generation
	sort.Strings(sortedCategories)

	// Join with "+" separator
	key := strings.Join(sortedCategories, "+")

	logger.L().Debugw("Created combination key",
		"original_categories", strings.Join(categories, ","),
		"sorted_categories", strings.Join(sortedCategories, ","),
		"combination_key", key)

	return key
}

// getMaximumBaseRisk finds the highest risk level among the base risks for the given categories
func getMaximumBaseRisk(riskScoring *config.RiskScoring, categories []string) string {
	// Risk level hierarchy: low < medium < high < critical
	riskHierarchy := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	maxRiskLevel := 0
	maxRiskName := riskScoring.Default
	foundAny := false

	for _, category := range categories {
		if baseRisk, exists := riskScoring.Base[category]; exists {
			foundAny = true
			if level, validRisk := riskHierarchy[baseRisk]; validRisk {
				if level > maxRiskLevel {
					maxRiskLevel = level
					maxRiskName = baseRisk
				}
				logger.L().Debugw("Evaluated category base risk",
					"category", category,
					"base_risk", baseRisk,
					"risk_level", level)
			} else {
				logger.L().Warnw("Invalid risk level found in base mapping",
					"category", category,
					"invalid_risk", baseRisk)
			}
		} else {
			logger.L().Warnw("Category not found in base risk mapping",
				"category", category)
		}
	}

	// If no valid categories were found, use default
	if !foundAny {
		logger.L().Debugw("No valid categories found in base mapping, using default",
			"default_risk", riskScoring.Default)
		return riskScoring.Default
	}

	return maxRiskName
}

// ValidateRiskLevel checks if a risk level is valid according to the hierarchy
func ValidateRiskLevel(riskLevel string) bool {
	validLevels := map[string]bool{
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}
	return validLevels[riskLevel]
}

// CompareRiskLevels compares two risk levels and returns:
// -1 if level1 < level2
//
//	0 if level1 == level2
//	1 if level1 > level2
//
// Returns 0 for invalid risk levels
func CompareRiskLevels(level1, level2 string) int {
	riskHierarchy := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	val1, valid1 := riskHierarchy[level1]
	val2, valid2 := riskHierarchy[level2]

	if !valid1 || !valid2 {
		return 0
	}

	if val1 < val2 {
		return -1
	} else if val1 > val2 {
		return 1
	}
	return 0
}

// GetRiskLevelValue returns the numeric value of a risk level (1-4)
// Returns 0 for invalid risk levels
func GetRiskLevelValue(riskLevel string) int {
	riskHierarchy := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	return riskHierarchy[riskLevel]
}

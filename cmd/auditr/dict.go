package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaibhaw-/AuditR/internal/auditr/config"
)

var dictFile string
var riskFile string

var dictCmd = &cobra.Command{
	Use:   "dict",
	Short: "Validate sensitivity dictionaries and risk scoring configs",
}

var dictValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate sensitivity dictionary and risk scoring JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		if dictFile == "" || riskFile == "" {
			return fmt.Errorf("--dict and --risk are required")
		}

		df, err := os.Open(dictFile)
		if err != nil {
			return fmt.Errorf("open dict file: %w", err)
		}
		defer df.Close()

		dict, categories, err := config.ValidateDict(df)
		if err != nil {
			return fmt.Errorf("dictionary validation failed: %w", err)
		}

		rf, err := os.Open(riskFile)
		if err != nil {
			return fmt.Errorf("open risk file: %w", err)
		}
		defer rf.Close()

		_, err = config.ValidateRiskScoring(rf, categories)
		if err != nil {
			return fmt.Errorf("risk scoring validation failed: %w", err)
		}

		fmt.Fprintf(os.Stdout, "dictionary and risk scoring validated successfully\n")
		fmt.Fprintf(os.Stdout, "categories: %v, negatives: %d\n", len(dict.Categories), len(dict.Negative))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dictCmd)
	dictCmd.AddCommand(dictValidateCmd)

	dictValidateCmd.Flags().StringVar(&dictFile, "dict", "", "Path to sensitivity dictionary JSON file")
	dictValidateCmd.Flags().StringVar(&riskFile, "risk", "", "Path to risk scoring JSON file")

	_ = dictValidateCmd.MarkFlagRequired("dict")
	_ = dictValidateCmd.MarkFlagRequired("risk")
}

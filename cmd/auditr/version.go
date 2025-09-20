package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show AuditR version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AuditR %s\n", Version)
	},
}

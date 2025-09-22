package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
)

var (
	cfgFile string
	Version = "v0.1"
	build   = "dev"
	rootCmd = &cobra.Command{
		Use:   "auditr",
		Short: "AuditR - tamper-evident DB audit pipeline",
		Long:  "AuditR: parse, enrich, sign and verify DB audit logs (practicum scope).",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// load config
			if cfgFile != "" {
				viper.SetConfigFile(cfgFile)
			} else {
				// default: ./config.yaml
				viper.SetConfigFile("config.yaml")
			}
			if err := viper.ReadInConfig(); err != nil {
				// It's okay to continue without config in some CLI flows; only error for commands that need it.
				// But we still log a note.
				fmt.Fprintf(os.Stderr, "Warning: could not read config (%v). Using defaults and flags.\n", err)
			}
			if err := config.Load(viper.GetViper()); err != nil {
				return err
			}

			// init logger
			cfg := config.Get()
			if err := logger.InitLogger(logger.LogConfig{
				Level:        cfg.Logging.Level,
				ConsoleLevel: cfg.Logging.ConsoleLevel,
				DebugFile:    cfg.Logging.DebugFile,
				InfoFile:     cfg.Logging.InfoFile,
				Development:  cfg.Logging.Development,
			}); err != nil {
				return fmt.Errorf("init logger: %w", err)
			}
			return nil
		},
	}
)

func init() {
	cobra.OnInitialize()
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	// add subcommands
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(versionCmd)
	// other commands (enrich, verify, etc.) to be added similarly
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

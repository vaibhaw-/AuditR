package main

import (
	"flag"
	"fmt"
	"os"

	loadr "github.com/vaibhaw-/AuditR/internal/loadr"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "load":
		loadCmd := flag.NewFlagSet("load", flag.ExitOnError)
		configPath := loadCmd.String("config", "", "Path to config file")
		loadCmd.Parse(os.Args[2:])
		if *configPath == "" {
			fmt.Println("Error: --config is required for 'load'")
			loadCmd.Usage()
			os.Exit(1)
		}
		fmt.Printf("Running 'load' with config: %s\n", *configPath)
		loadr.Load(configPath)

	case "run":
		runCmd := flag.NewFlagSet("run", flag.ExitOnError)
		configPath := runCmd.String("config", "", "Path to config file")
		runCmd.Parse(os.Args[2:])
		if *configPath == "" {
			fmt.Println("Error: --config is required for 'run'")
			runCmd.Usage()
			os.Exit(1)
		}
		fmt.Printf("Running 'run' with config: %s\n", *configPath)
		loadr.Run(configPath)

	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Printf("Unknown subcommand: %s\n\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`Usage: loadr <subcommand> --config <path>`)
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  load    --config <path>   Load data using config file")
	fmt.Println("  run     --config <path>   Run process using config file")
	fmt.Println("  help                      Show this help message")
}

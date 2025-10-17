package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLoad_Defaults(t *testing.T) {
	v := viper.New()
	if err := Load(v); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Get()
	if cfg.Version != "0.1" {
		t.Errorf("default Version = %v, want 0.1", cfg.Version)
	}
	if cfg.Hashing.CheckpointInterval != "file_end" {
		t.Errorf("default CheckpointInterval = %v, want file_end", cfg.Hashing.CheckpointInterval)
	}
	if cfg.Output.Format != "ndjson" {
		t.Errorf("default Format = %v, want ndjson", cfg.Output.Format)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default Level = %v, want info", cfg.Logging.Level)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	v := viper.New()
	v.Set("version", "0.2")
	v.Set("enrichment.schema_file", "./schema.sql")
	v.Set("enrichment.dict_file", "./dict.json")
	v.Set("enrichment.risk_file", "./risk.json")
	v.Set("hashing.state_file", "./state.json")
	v.Set("hashing.checkpoint_dir", "./checkpoints")
	v.Set("hashing.checkpoint_interval", "1h")
	v.Set("signing.private_key_path", "./private.pem")
	v.Set("output.format", "csv")
	v.Set("output.dir", "./output")
	v.Set("output.reject_file", "./rejected.jsonl")
	v.Set("input.mode", "file")
	v.Set("input.file_path", "./input.log")
	v.Set("logging.level", "debug")
	v.Set("logging.run_log", "./run.jsonl")

	if err := Load(v); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Get()

	// Check all fields
	if cfg.Version != "0.2" {
		t.Errorf("Version = %v, want 0.2", cfg.Version)
	}

	// Enrichment
	if cfg.Enrichment.SchemaFile != "./schema.sql" {
		t.Errorf("SchemaFile = %v, want ./schema.sql", cfg.Enrichment.SchemaFile)
	}
	if cfg.Enrichment.DictFile != "./dict.json" {
		t.Errorf("DictFile = %v, want ./dict.json", cfg.Enrichment.DictFile)
	}
	if cfg.Enrichment.RiskFile != "./risk.json" {
		t.Errorf("RiskFile = %v, want ./risk.json", cfg.Enrichment.RiskFile)
	}

	// Hashing
	if cfg.Hashing.StateFile != "./state.json" {
		t.Errorf("StateFile = %v, want ./state.json", cfg.Hashing.StateFile)
	}
	if cfg.Hashing.CheckpointDir != "./checkpoints" {
		t.Errorf("CheckpointDir = %v, want ./checkpoints", cfg.Hashing.CheckpointDir)
	}
	if cfg.Hashing.CheckpointInterval != "1h" {
		t.Errorf("CheckpointInterval = %v, want 1h", cfg.Hashing.CheckpointInterval)
	}

	// Signing
	if cfg.Signing.PrivateKeyPath != "./private.pem" {
		t.Errorf("PrivateKeyPath = %v, want ./private.pem", cfg.Signing.PrivateKeyPath)
	}
	// Algorithm removed; ECDSA P-256 is fixed in implementation

	// Output
	if cfg.Output.Format != "csv" {
		t.Errorf("Format = %v, want csv", cfg.Output.Format)
	}
	if cfg.Output.Dir != "./output" {
		t.Errorf("Dir = %v, want ./output", cfg.Output.Dir)
	}
	if cfg.Output.RejectFile != "./rejected.jsonl" {
		t.Errorf("RejectFile = %v, want ./rejected.jsonl", cfg.Output.RejectFile)
	}

	// Input
	if cfg.Input.Mode != "file" {
		t.Errorf("Mode = %v, want file", cfg.Input.Mode)
	}
	if cfg.Input.FilePath != "./input.log" {
		t.Errorf("FilePath = %v, want ./input.log", cfg.Input.FilePath)
	}

	// Logging
	if cfg.Logging.Level != "debug" {
		t.Errorf("Level = %v, want debug", cfg.Logging.Level)
	}
	if cfg.Logging.RunLog != "./run.jsonl" {
		t.Errorf("RunLog = %v, want ./run.jsonl", cfg.Logging.RunLog)
	}
}

func TestLoad_InvalidConfig(t *testing.T) {
	v := viper.New()
	v.Set("version", 123) // Invalid type for version (should be string)

	if err := Load(v); err == nil {
		t.Error("Load() error = nil, want error for invalid config")
	}
}

func TestGet_NilConfig(t *testing.T) {
	// Reset global config
	cfg = nil

	// Get should return empty config when not loaded
	c := Get()
	if c == nil {
		t.Error("Get() = nil, want empty config")
	}
	if c.Version != "" {
		t.Errorf("Version = %v, want empty string", c.Version)
	}
}

func TestGet_Singleton(t *testing.T) {
	// Reset global config
	cfg = nil

	// First call should create empty config
	c1 := Get()
	if c1 == nil {
		t.Fatal("Get() returned nil")
	}

	// Second call should return same instance
	c2 := Get()
	if c2 != c1 {
		t.Error("Get() returned different instance")
	}
}

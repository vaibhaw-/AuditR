package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type LoggingCfg struct {
	Level string `mapstructure:"level"`
}

type HashingCfg struct {
	StateFile          string `mapstructure:"state_file"`
	CheckpointDir      string `mapstructure:"checkpoint_dir"`
	CheckpointInterval string `mapstructure:"checkpoint_interval"`
}

type EnrichmentCfg struct {
	SchemaFile string `mapstructure:"schema_file"`
	DictFile   string `mapstructure:"dict_file"`
	RiskFile   string `mapstructure:"risk_file"`
}

type OutputCfg struct {
	Format string `mapstructure:"format"`
	Dir    string `mapstructure:"dir"`
}

type Config struct {
	Version    string        `mapstructure:"version"`
	InputMode  string        `mapstructure:"input_mode"`
	Enrichment EnrichmentCfg `mapstructure:"enrichment"`
	Hashing    HashingCfg    `mapstructure:"hashing"`
	Signing    struct {
		PrivateKeyPath string `mapstructure:"private_key_path"`
		Algorithm      string `mapstructure:"algorithm"`
	} `mapstructure:"signing"`
	Output  OutputCfg  `mapstructure:"output"`
	Logging LoggingCfg `mapstructure:"logging"`
}

var cfg *Config

// Load populates global config from a viper instance
func Load(v *viper.Viper) error {
	// set defaults
	v.SetDefault("version", "0.1")
	v.SetDefault("hashing.checkpoint_interval", "file_end")
	v.SetDefault("output.format", "ndjson")
	v.SetDefault("logging.level", "info")

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	cfg = &c
	return nil
}

func Get() *Config {
	if cfg == nil {
		cfg = &Config{}
	}
	return cfg
}

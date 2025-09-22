package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type LoggingCfg struct {
	// Level is the minimum level to log: debug, info, warn, error
	Level string `mapstructure:"level"`
	// ConsoleLevel is the minimum level to show on console (can be higher than file level)
	ConsoleLevel string `mapstructure:"console_level"`
	// DebugFile is the path to the debug log file (optional)
	DebugFile string `mapstructure:"debug_file"`
	// InfoFile is the path to the info log file (optional)
	InfoFile string `mapstructure:"info_file"`
	// RunLog is the path to the run summary log file
	RunLog string `mapstructure:"run_log"`
	// Development enables development mode with more verbose output
	Development bool `mapstructure:"development"`
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

type InputCfg struct {
	Mode     string `mapstructure:"mode"`
	FilePath string `mapstructure:"file_path"`
}

type OutputCfg struct {
	Format     string `mapstructure:"format"`
	Dir        string `mapstructure:"dir"`
	RejectFile string `mapstructure:"reject_file"` // Path to file for storing rejected/skipped log entries
}

type Config struct {
	Version    string        `mapstructure:"version"`
	Enrichment EnrichmentCfg `mapstructure:"enrichment"`
	Hashing    HashingCfg    `mapstructure:"hashing"`
	Signing    struct {
		PrivateKeyPath string `mapstructure:"private_key_path"`
		Algorithm      string `mapstructure:"algorithm"`
	} `mapstructure:"signing"`
	Output  OutputCfg  `mapstructure:"output"`
	Input   InputCfg   `mapstructure:"input"`
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

	// First check version type before unmarshaling
	if ver := v.Get("version"); ver != nil {
		if _, ok := ver.(string); !ok {
			return fmt.Errorf("version must be a string")
		}
	}

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

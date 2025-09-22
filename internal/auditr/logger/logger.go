// Package logger provides a structured logging facility for AuditR.
// It supports both console and file output with different log levels
// and formats optimized for human readability and debugging.
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *zap.SugaredLogger
)

// LogConfig holds configuration for the logger
type LogConfig struct {
	// Level is the minimum level to log: debug, info, warn, error
	Level string
	// ConsoleLevel is the minimum level to show on console (can be higher than file level)
	ConsoleLevel string
	// DebugFile is the path to the debug log file (optional)
	DebugFile string
	// InfoFile is the path to the info log file (optional)
	InfoFile string
	// Development enables development mode with more verbose output
	Development bool
}

// InitLogger initializes a global sugared logger with the given configuration.
// It supports both console and file output with different levels.
func InitLogger(cfg LogConfig) error {
	// Set default level if not specified
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	if cfg.ConsoleLevel == "" {
		cfg.ConsoleLevel = cfg.Level
	}

	// Create encoder configs for different outputs
	consoleCfg := zap.NewDevelopmentEncoderConfig()
	consoleCfg.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")
	consoleCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleCfg.EncodeCaller = zapcore.ShortCallerEncoder

	fileCfg := zap.NewProductionEncoderConfig()
	fileCfg.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	fileCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	fileCfg.EncodeCaller = zapcore.ShortCallerEncoder

	// Create cores for different outputs
	var cores []zapcore.Core

	// Console output (always enabled)
	consoleLevel := getZapLevel(cfg.ConsoleLevel)
	consoleSyncer := zapcore.Lock(os.Stderr)
	cores = append(cores, zapcore.NewCore(
		zapcore.NewConsoleEncoder(consoleCfg),
		consoleSyncer,
		consoleLevel,
	))

	// Debug file output
	if cfg.DebugFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.DebugFile), 0755); err != nil {
			return fmt.Errorf("create debug log directory: %w", err)
		}
		debugFile, err := os.OpenFile(cfg.DebugFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open debug log file: %w", err)
		}
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(fileCfg),
			zapcore.Lock(debugFile),
			zapcore.DebugLevel,
		))
	}

	// Info file output
	if cfg.InfoFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.InfoFile), 0755); err != nil {
			return fmt.Errorf("create info log directory: %w", err)
		}
		infoFile, err := os.OpenFile(cfg.InfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open info log file: %w", err)
		}
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(fileCfg),
			zapcore.Lock(infoFile),
			zapcore.InfoLevel,
		))
	}

	// Create logger
	core := zapcore.NewTee(cores...)
	options := []zap.Option{
		zap.AddCaller(),
		zap.AddCallerSkip(1),
	}
	if cfg.Development {
		options = append(options, zap.Development())
	}

	z := zap.New(core, options...)
	logger = z.Sugar()
	return nil
}

// L returns the global sugared logger.
// If InitLogger has not been called, it initializes with default settings.
func L() *zap.SugaredLogger {
	if logger == nil {
		_ = InitLogger(LogConfig{
			Level:        "info",
			ConsoleLevel: "info",
			Development:  true,
		})
	}
	return logger
}

// getZapLevel converts a string level to zapcore.Level
func getZapLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

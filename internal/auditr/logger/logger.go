package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *zap.SugaredLogger
)

// InitLogger initializes a global sugared logger at the given level.
func InitLogger(level string) error {
	cfg := zap.NewProductionConfig()
	switch level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	z, err := cfg.Build()
	if err != nil {
		return err
	}

	logger = z.Sugar()
	return nil
}

// L returns the global sugared logger.
// If InitLogger has not been called, it initializes at info level.
func L() *zap.SugaredLogger {
	if logger == nil {
		_ = InitLogger("info")
	}
	return logger
}

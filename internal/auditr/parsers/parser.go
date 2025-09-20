package parsers

import (
	"context"
	"errors"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
)

// ErrSkipLine indicates the parser couldn't parse the line but processing should continue.
var ErrSkipLine = errors.New("skip line")

type ParserOptions struct {
	EmitRaw bool
	Config  *config.Config
}

// Parser defines a parser capable of converting a raw log line to an NDJSON event object.
type Parser interface {
	// ParseLine should return a Event representing the event, or ErrSkipLine if the line is ignorable,
	// or other error for fatal parse failures.
	ParseLine(ctx context.Context, line string) (*Event, error)
}

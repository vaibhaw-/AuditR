package parsers

import (
	"fmt"
)

type Factory struct{}

func NewFactory() *Factory {
	return &Factory{}
}

// NewParser returns a Parser for the given dbType ("postgres" or "mysql")
func (f *Factory) NewParser(dbType string, opts ParserOptions) (Parser, error) {
	switch dbType {
	case "postgres", "pg", "postgresql":
		return NewPostgresParser(opts), nil
	case "mysql", "percona":
		return NewMySQLParser(opts), nil
	default:
		return nil, fmt.Errorf("unsupported db type: %s", dbType)
	}
}

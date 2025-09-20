package parsers

import (
	"context"
	"strings"
)

type MySQLParser struct {
	opts ParserOptions
}

func NewMySQLParser(opts ParserOptions) *MySQLParser {
	return &MySQLParser{opts: opts}
}

func (p *MySQLParser) ParseLine(ctx context.Context, line string) (*Event, error) {
	// Percona Audit plugin format varies. This is a skeleton.
	if strings.TrimSpace(line) == "" {
		return nil, ErrSkipLine
	}

	// crude logic to find SQL between quotes or after first tab etc.
	// Implement complete Percona log parsing here.
	q := extractSQLFromMySQLLine(line)
	if q == "" {
		return nil, ErrSkipLine
	}

	evt := map[string]interface{}{
		"event_id":   "",
		"timestamp":  "",
		"db_system":  "mysql",
		"query_type": detectQueryType(q),
		"raw_query": func() interface{} {
			if p.opts.EmitRaw {
				return q
			}
			return nil
		}(),
	}

	for k, v := range evt {
		if v == nil {
			delete(evt, k)
		}
	}

	return nil, nil
}

func extractSQLFromMySQLLine(line string) string {
	// naive: find first occurrence of 'Query' or quotes
	if i := strings.Index(line, "Query"); i >= 0 {
		// everything after 'Query' could be the SQL in some formats
		parts := strings.SplitN(line[i:], " ", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	// fallback: try quotes
	first := strings.Index(line, "\"")
	if first >= 0 {
		last := strings.LastIndex(line, "\"")
		if last > first {
			return line[first+1 : last]
		}
	}
	return ""
}

package parsers

import (
	"fmt"
	"testing"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
)

func TestFactory_NewParser(t *testing.T) {
	tests := []struct {
		name    string
		dbType  string
		opts    ParserOptions
		want    string // expected parser type
		wantErr bool
	}{
		{
			name:    "PostgreSQL",
			dbType:  "postgres",
			opts:    ParserOptions{EmitRaw: true},
			want:    "*parsers.PostgresParser",
			wantErr: false,
		},
		{
			name:    "PostgreSQL (pg alias)",
			dbType:  "pg",
			opts:    ParserOptions{EmitRaw: false},
			want:    "*parsers.PostgresParser",
			wantErr: false,
		},
		{
			name:    "PostgreSQL (full name)",
			dbType:  "postgresql",
			opts:    ParserOptions{EmitRaw: true},
			want:    "*parsers.PostgresParser",
			wantErr: false,
		},
		{
			name:    "MySQL",
			dbType:  "mysql",
			opts:    ParserOptions{EmitRaw: true},
			want:    "*parsers.MySQLParser",
			wantErr: false,
		},
		{
			name:    "MySQL (percona alias)",
			dbType:  "percona",
			opts:    ParserOptions{EmitRaw: false},
			want:    "*parsers.MySQLParser",
			wantErr: false,
		},
		{
			name:    "Invalid DB type",
			dbType:  "invalid",
			opts:    ParserOptions{},
			want:    "",
			wantErr: true,
		},
		{
			name:    "Empty DB type",
			dbType:  "",
			opts:    ParserOptions{},
			want:    "",
			wantErr: true,
		},
		{
			name:   "With config",
			dbType: "postgres",
			opts: ParserOptions{
				EmitRaw: true,
				Config: &config.Config{
					Version: "0.1",
				},
			},
			want:    "*parsers.PostgresParser",
			wantErr: false,
		},
	}

	factory := NewFactory()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := factory.NewParser(tt.dbType, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewParser() error = nil, wantErr %v", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewParser() unexpected error = %v", err)
			}

			// Check parser type
			gotType := fmt.Sprintf("%T", got)
			if gotType != tt.want {
				t.Errorf("NewParser() got = %v, want %v", gotType, tt.want)
			}

			// Verify parser options were passed through
			switch p := got.(type) {
			case *PostgresParser:
				if p.opts.EmitRaw != tt.opts.EmitRaw {
					t.Errorf("PostgresParser.opts.EmitRaw = %v, want %v", p.opts.EmitRaw, tt.opts.EmitRaw)
				}
				if p.opts.Config != tt.opts.Config {
					t.Errorf("PostgresParser.opts.Config = %v, want %v", p.opts.Config, tt.opts.Config)
				}
			case *MySQLParser:
				if p.opts.EmitRaw != tt.opts.EmitRaw {
					t.Errorf("MySQLParser.opts.EmitRaw = %v, want %v", p.opts.EmitRaw, tt.opts.EmitRaw)
				}
				if p.opts.Config != tt.opts.Config {
					t.Errorf("MySQLParser.opts.Config = %v, want %v", p.opts.Config, tt.opts.Config)
				}
			}
		})
	}
}

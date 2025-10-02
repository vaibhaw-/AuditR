package enrich

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSchemaCSV(t *testing.T) {
	tests := []struct {
		name        string
		csvContent  string
		expectError bool
		expected    SchemaMap
	}{
		{
			name: "valid_postgres_schema",
			csvContent: `db_name,schema_name,table_name,column_name,column_type
practicumdb,healthcare,patient,patient_id,uuid
practicumdb,healthcare,patient,ssn,character varying
practicumdb,healthcare,patient,email,USER-DEFINED
practicumdb,payments,payment_method,card_last4,character`,
			expectError: false,
			expected: SchemaMap{
				"healthcare": {
					"patient": {
						"patient_id": "UUID",
						"ssn":        "VARCHAR",
						"email":      "TEXT",
					},
				},
				"payments": {
					"payment_method": {
						"card_last4": "CHAR",
					},
				},
			},
		},
		{
			name: "valid_mysql_schema",
			csvContent: `db_name,schema_name,table_name,column_name,column_type
practicumdb,default,healthcare_patient,patient_id,char(36)
practicumdb,default,healthcare_patient,ssn,varchar(11)
practicumdb,default,payments_payment_method,card_last4,char(4)
practicumdb,default,pharmacy_drug,price,decimal(12,2)`,
			expectError: false,
			expected: SchemaMap{
				"default": {
					"healthcare_patient": {
						"patient_id": "CHAR",
						"ssn":        "VARCHAR",
					},
					"payments_payment_method": {
						"card_last4": "CHAR",
					},
					"pharmacy_drug": {
						"price": "DECIMAL",
					},
				},
			},
		},
		{
			name: "invalid_header",
			csvContent: `wrong,header,format
value1,value2,value3`,
			expectError: true,
		},
		{
			name:        "empty_file",
			csvContent:  `db_name,schema_name,table_name,column_name,column_type`,
			expectError: false,
			expected:    SchemaMap{},
		},
		{
			name: "malformed_rows_skipped",
			csvContent: `db_name,schema_name,table_name,column_name,column_type
practicumdb,healthcare,patient,patient_id,uuid
incomplete,row
practicumdb,healthcare,patient,ssn,varchar`,
			expectError: false,
			expected: SchemaMap{
				"healthcare": {
					"patient": {
						"patient_id": "UUID",
						"ssn":        "VARCHAR",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary CSV file
			tmpFile, err := os.CreateTemp("", "schema_test_*.csv")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.csvContent)
			require.NoError(t, err)
			tmpFile.Close()

			// Test the function
			result, err := LoadSchemaCSV(tmpFile.Name())

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoadSchemaCSV_RealFiles(t *testing.T) {
	// Test with actual schema files from the project
	testCases := []struct {
		name     string
		filename string
		checks   func(t *testing.T, schema SchemaMap)
	}{
		{
			name:     "postgres_schema",
			filename: "postgres_schema.csv",
			checks: func(t *testing.T, schema SchemaMap) {
				// Check that healthcare schema exists
				assert.Contains(t, schema, "healthcare")

				// Check that patient table exists in healthcare schema
				assert.Contains(t, schema["healthcare"], "patient")

				// Check specific columns and their normalized types
				patientCols := schema["healthcare"]["patient"]
				assert.Equal(t, "UUID", patientCols["patient_id"])
				assert.Equal(t, "VARCHAR", patientCols["ssn"])
				assert.Equal(t, "TEXT", patientCols["email"]) // USER-DEFINED -> TEXT
				assert.Equal(t, "DATE", patientCols["dob"])

				// Check payments schema
				assert.Contains(t, schema, "payments")
				assert.Contains(t, schema["payments"], "payment_method")
				paymentCols := schema["payments"]["payment_method"]
				assert.Equal(t, "CHAR", paymentCols["card_last4"])
			},
		},
		{
			name:     "mysql_schema",
			filename: "mysql_schema.csv",
			checks: func(t *testing.T, schema SchemaMap) {
				// MySQL uses "default" schema
				assert.Contains(t, schema, "default")

				// Check healthcare_patient table (MySQL naming convention)
				assert.Contains(t, schema["default"], "healthcare_patient")

				// Check specific columns and their normalized types
				patientCols := schema["default"]["healthcare_patient"]
				assert.Equal(t, "CHAR", patientCols["patient_id"]) // char(36) -> CHAR
				assert.Equal(t, "VARCHAR", patientCols["ssn"])     // varchar(11) -> VARCHAR
				assert.Equal(t, "VARCHAR", patientCols["email"])   // varchar(255) -> VARCHAR
				assert.Equal(t, "DATE", patientCols["dob"])

				// Check payments table
				assert.Contains(t, schema["default"], "payments_payment_method")
				paymentCols := schema["default"]["payments_payment_method"]
				assert.Equal(t, "CHAR", paymentCols["card_last4"]) // char(4) -> CHAR
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct path to schema file (assuming test runs from project root)
			schemaPath := filepath.Join("..", "..", "..", tc.filename)

			// Check if file exists, skip test if not found
			if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
				t.Skipf("Schema file not found: %s", schemaPath)
			}

			schema, err := LoadSchemaCSV(schemaPath)
			require.NoError(t, err)

			// Run specific checks for this schema
			tc.checks(t, schema)
		})
	}
}

func TestNormalizeColumnType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Basic types
		{"varchar(255)", "VARCHAR"},
		{"char(36)", "CHAR"},
		{"text", "TEXT"},
		{"integer", "INT"},

		// PostgreSQL specific
		{"character varying", "VARCHAR"},
		{"character", "CHAR"},
		{"timestamp with time zone", "TIMESTAMPTZ"},
		{"timestamp without time zone", "TIMESTAMP"},
		{"double precision", "DOUBLE"},
		{"USER-DEFINED", "TEXT"},

		// MySQL specific
		{"tinyint(1)", "TINYINT"},
		{"int", "INT"},
		{"bigint", "BIGINT"},
		{"smallint", "SMALLINT"},
		{"decimal(12,2)", "DECIMAL"},
		{"enum('PENDING','FILLED','CANCELLED')", "VARCHAR"},

		// Case insensitive
		{"VARCHAR(100)", "VARCHAR"},
		{"Text", "TEXT"},
		{"CHAR(4)", "CHAR"},

		// Edge cases
		{"", ""},
		{"   varchar(255)   ", "VARCHAR"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeColumnType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSchemaMap_Methods(t *testing.T) {
	schema := SchemaMap{
		"healthcare": {
			"patient": {
				"patient_id": "UUID",
				"ssn":        "VARCHAR",
				"email":      "TEXT",
			},
			"encounter": {
				"encounter_id": "UUID",
				"diagnosis":    "TEXT",
			},
		},
		"payments": {
			"payment_method": {
				"card_last4": "CHAR",
			},
		},
	}

	t.Run("GetColumnType", func(t *testing.T) {
		// Existing column
		assert.Equal(t, "VARCHAR", schema.GetColumnType("healthcare", "patient", "ssn"))

		// Non-existing column
		assert.Equal(t, "", schema.GetColumnType("healthcare", "patient", "nonexistent"))

		// Non-existing table
		assert.Equal(t, "", schema.GetColumnType("healthcare", "nonexistent", "ssn"))

		// Non-existing schema
		assert.Equal(t, "", schema.GetColumnType("nonexistent", "patient", "ssn"))
	})

	t.Run("HasColumn", func(t *testing.T) {
		assert.True(t, schema.HasColumn("healthcare", "patient", "ssn"))
		assert.False(t, schema.HasColumn("healthcare", "patient", "nonexistent"))
	})

	t.Run("GetTableColumns", func(t *testing.T) {
		cols := schema.GetTableColumns("healthcare", "patient")
		expected := map[string]string{
			"patient_id": "UUID",
			"ssn":        "VARCHAR",
			"email":      "TEXT",
		}
		assert.Equal(t, expected, cols)

		// Non-existing table
		assert.Nil(t, schema.GetTableColumns("healthcare", "nonexistent"))
	})

	t.Run("GetSchemaNames", func(t *testing.T) {
		names := schema.GetSchemaNames()
		assert.Len(t, names, 2)
		assert.Contains(t, names, "healthcare")
		assert.Contains(t, names, "payments")
	})

	t.Run("GetTableNames", func(t *testing.T) {
		names := schema.GetTableNames("healthcare")
		assert.Len(t, names, 2)
		assert.Contains(t, names, "patient")
		assert.Contains(t, names, "encounter")

		// Non-existing schema
		assert.Empty(t, schema.GetTableNames("nonexistent"))
	})
}

func TestLoadSchemaCSV_FileNotFound(t *testing.T) {
	_, err := LoadSchemaCSV("/nonexistent/path/schema.csv")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open schema file")
}

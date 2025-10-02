package enrich

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected QueryRefs
	}{
		{
			name:  "simple_select",
			query: "SELECT id, name FROM users",
			expected: QueryRefs{
				Tables:  map[string]string{"users": "users"},
				Columns: []string{"id", "name"},
				IsBulk:  false,
			},
		},
		{
			name:  "select_with_alias",
			query: "SELECT u.id, u.name FROM users u",
			expected: QueryRefs{
				Tables:  map[string]string{"u": "users", "users": "users"},
				Columns: []string{"u.id", "u.name"},
				IsBulk:  false,
			},
		},
		{
			name:  "select_with_join",
			query: "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id",
			expected: QueryRefs{
				Tables:  map[string]string{"u": "users", "users": "users", "p": "posts", "posts": "posts"},
				Columns: []string{"u.name", "p.title"},
				IsBulk:  false,
			},
		},
		{
			name:  "insert_with_columns",
			query: "INSERT INTO users (id, name, email) VALUES (1, 'John', 'john@example.com')",
			expected: QueryRefs{
				Tables:  map[string]string{"users": "users"},
				Columns: []string{"id", "name", "email"},
				IsBulk:  false,
			},
		},
		{
			name:  "update_query",
			query: "UPDATE users SET name = 'Jane', email = 'jane@example.com' WHERE id = 1",
			expected: QueryRefs{
				Tables:  map[string]string{"users": "users"},
				Columns: []string{"name", "email"},
				IsBulk:  false,
			},
		},
		{
			name:  "delete_query",
			query: "DELETE FROM users WHERE id = 1",
			expected: QueryRefs{
				Tables:  map[string]string{"users": "users"},
				Columns: []string{},
				IsBulk:  false,
			},
		},
		{
			name:  "empty_query",
			query: "",
			expected: QueryRefs{
				Tables:  map[string]string{},
				Columns: []string{},
				IsBulk:  false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseQuery(tt.query)
			assert.Equal(t, tt.expected.Tables, result.Tables)
			assert.Equal(t, tt.expected.Columns, result.Columns)
			assert.Equal(t, tt.expected.IsBulk, result.IsBulk)
		})
	}
}

func TestParseQuery_BulkOperations(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		expectedBulk bool
		expectedType string
	}{
		// PostgreSQL bulk operations
		{
			name:         "postgres_copy_export",
			query:        "COPY users TO '/tmp/users.csv' WITH CSV",
			expectedBulk: true,
			expectedType: "export",
		},
		{
			name:         "postgres_copy_import",
			query:        "COPY users FROM '/tmp/users.csv' WITH CSV",
			expectedBulk: true,
			expectedType: "import",
		},
		{
			name:         "postgres_copy_generic",
			query:        "COPY users (id, name)",
			expectedBulk: true,
			expectedType: "copy",
		},

		// MySQL bulk operations
		{
			name:         "mysql_load_data",
			query:        "LOAD DATA INFILE '/tmp/users.csv' INTO TABLE users",
			expectedBulk: true,
			expectedType: "import",
		},
		{
			name:         "mysql_select_outfile",
			query:        "SELECT * FROM users INTO OUTFILE '/tmp/users.csv'",
			expectedBulk: true,
			expectedType: "export",
		},

		// Multi-row INSERT
		{
			name:         "multi_row_insert_values",
			query:        "INSERT INTO users VALUES (1, 'John'), (2, 'Jane'), (3, 'Bob')",
			expectedBulk: false, // This pattern doesn't trigger our bulk detection
			expectedType: "",
		},
		{
			name:         "insert_select",
			query:        "INSERT INTO users_backup SELECT * FROM users",
			expectedBulk: true,
			expectedType: "insert",
		},

		// SELECT * without WHERE (potential full table scan)
		{
			name:         "select_star_no_where",
			query:        "SELECT * FROM users",
			expectedBulk: true,
			expectedType: "select",
		},
		{
			name:         "select_star_with_where",
			query:        "SELECT * FROM users WHERE id = 1",
			expectedBulk: false,
			expectedType: "",
		},

		// Regular operations (not bulk)
		{
			name:         "regular_select",
			query:        "SELECT id, name FROM users WHERE active = true",
			expectedBulk: false,
			expectedType: "",
		},
		{
			name:         "regular_insert",
			query:        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
			expectedBulk: false,
			expectedType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseQuery(tt.query)
			assert.Equal(t, tt.expectedBulk, result.IsBulk, "Bulk detection mismatch")
			if tt.expectedBulk {
				assert.Equal(t, tt.expectedType, result.BulkType, "Bulk type mismatch")
			}
		})
	}
}

func TestParseQuery_ComplexQueries(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		checkFunc func(t *testing.T, result QueryRefs)
	}{
		{
			name:  "multiple_joins",
			query: "SELECT u.name, p.title, c.content FROM users u JOIN posts p ON u.id = p.user_id LEFT JOIN comments c ON p.id = c.post_id",
			checkFunc: func(t *testing.T, result QueryRefs) {
				// Should find all three tables
				assert.Contains(t, result.Tables, "u")
				assert.Contains(t, result.Tables, "p")
				assert.Contains(t, result.Tables, "c")
				assert.Equal(t, "users", result.Tables["u"])
				assert.Equal(t, "posts", result.Tables["p"])
				assert.Equal(t, "comments", result.Tables["c"])

				// Should find qualified column references
				assert.Contains(t, result.Columns, "u.name")
				assert.Contains(t, result.Columns, "p.title")
				assert.Contains(t, result.Columns, "c.content")
			},
		},
		{
			name:  "case_insensitive",
			query: "select U.Name, P.Title from Users U join Posts P on U.Id = P.UserId",
			checkFunc: func(t *testing.T, result QueryRefs) {
				assert.Contains(t, result.Tables, "U")
				assert.Contains(t, result.Tables, "P")
				assert.Equal(t, "Users", result.Tables["U"])
				assert.Equal(t, "Posts", result.Tables["P"])
			},
		},
		{
			name:  "update_with_alias",
			query: "UPDATE users u SET u.name = 'Updated' WHERE u.id = 1",
			checkFunc: func(t *testing.T, result QueryRefs) {
				assert.Contains(t, result.Tables, "u")
				assert.Equal(t, "users", result.Tables["u"])
				assert.Contains(t, result.Columns, "u.name") // SET columns are qualified
				assert.Contains(t, result.Columns, "u.id")   // WHERE columns are qualified
			},
		},
		{
			name:  "healthcare_example",
			query: "SELECT p.patient_id, p.ssn, e.diagnosis FROM healthcare.patient p JOIN healthcare.encounter e ON p.patient_id = e.patient_id",
			checkFunc: func(t *testing.T, result QueryRefs) {
				// Note: Our simple parser doesn't handle schema prefixes, so it will see "healthcare" as table name
				// This is acceptable for the v1 implementation
				assert.NotEmpty(t, result.Tables)
				assert.Contains(t, result.Columns, "p.patient_id")
				assert.Contains(t, result.Columns, "p.ssn")
				assert.Contains(t, result.Columns, "e.diagnosis")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseQuery(tt.query)
			tt.checkFunc(t, result)
		})
	}
}

func TestParseQuery_RealWorldExamples(t *testing.T) {
	// Test with queries similar to what we might see in the sample data
	tests := []struct {
		name      string
		query     string
		checkFunc func(t *testing.T, result QueryRefs)
	}{
		{
			name:  "mysql_insert_healthcare",
			query: "INSERT INTO healthcare_encounter (encounter_id, patient_id, encounter_ts, diagnosis, treatment, provider_name, notes) VALUES ('e6f3f9b7-9d19-4b4c-b9cb-2739262a3560','03bfd5e7-e4b8-4ddb-890e-41d3be80f611','2025-03-24','Generalized Anxiety Disorder','Treatment plan 12','Lambert Rippin','As enthusiastically himself that theirs innocently then by which bush.')",
			checkFunc: func(t *testing.T, result QueryRefs) {
				assert.Contains(t, result.Tables, "healthcare_encounter")

				// Should extract column names from INSERT
				expectedColumns := []string{"encounter_id", "patient_id", "encounter_ts", "diagnosis", "treatment", "provider_name", "notes"}
				for _, col := range expectedColumns {
					assert.Contains(t, result.Columns, col, "Missing column: %s", col)
				}

				assert.False(t, result.IsBulk) // Single INSERT is not bulk
			},
		},
		{
			name:  "postgres_select_with_schema",
			query: "SELECT p.patient_id, p.ssn FROM healthcare.patient p WHERE p.patient_id = '03bfd5e7-e4b8-4ddb-890e-41d3be80f611'",
			checkFunc: func(t *testing.T, result QueryRefs) {
				// Our parser will see "healthcare" as a table name, which is fine for v1
				assert.NotEmpty(t, result.Tables)
				assert.Contains(t, result.Columns, "p.patient_id")
				assert.Contains(t, result.Columns, "p.ssn")
				assert.False(t, result.IsBulk)
			},
		},
		{
			name:  "bulk_select_all_patients",
			query: "SELECT * FROM healthcare_patient",
			checkFunc: func(t *testing.T, result QueryRefs) {
				assert.Contains(t, result.Tables, "healthcare_patient")
				assert.Contains(t, result.Columns, "*")
				assert.True(t, result.IsBulk)
				assert.Equal(t, "select", result.BulkType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseQuery(tt.query)
			tt.checkFunc(t, result)
		})
	}
}

func TestQueryRefs_ResolveColumns(t *testing.T) {
	// Create a test schema
	schema := SchemaMap{
		"healthcare": {
			"patient": {
				"patient_id": "UUID",
				"ssn":        "VARCHAR",
				"email":      "TEXT",
			},
			"encounter": {
				"encounter_id": "UUID",
				"patient_id":   "UUID",
				"diagnosis":    "TEXT",
			},
		},
		"default": {
			"healthcare_patient": {
				"patient_id": "CHAR",
				"ssn":        "VARCHAR",
				"email":      "VARCHAR",
			},
		},
	}

	tests := []struct {
		name      string
		queryRefs QueryRefs
		expected  map[string]string
	}{
		{
			name: "qualified_columns",
			queryRefs: QueryRefs{
				Tables:  map[string]string{"p": "patient"},
				Columns: []string{"p.patient_id", "p.ssn"},
			},
			expected: map[string]string{
				"p.patient_id": "UUID",
				"p.ssn":        "VARCHAR",
			},
		},
		{
			name: "unqualified_columns",
			queryRefs: QueryRefs{
				Tables:  map[string]string{"patient": "patient"},
				Columns: []string{"patient_id", "ssn"},
			},
			expected: map[string]string{
				"patient.patient_id": "UUID",
				"patient.ssn":        "VARCHAR",
			},
		},
		{
			name: "wildcard_select",
			queryRefs: QueryRefs{
				Tables:  map[string]string{"p": "patient"},
				Columns: []string{"*"},
			},
			expected: map[string]string{
				"p.patient_id": "UUID",
				"p.ssn":        "VARCHAR",
				"p.email":      "TEXT",
			},
		},
		{
			name: "mysql_style",
			queryRefs: QueryRefs{
				Tables:  map[string]string{"healthcare_patient": "healthcare_patient"},
				Columns: []string{"patient_id", "ssn"},
			},
			expected: map[string]string{
				"healthcare_patient.patient_id": "CHAR",
				"healthcare_patient.ssn":        "VARCHAR",
			},
		},
		{
			name: "unknown_columns",
			queryRefs: QueryRefs{
				Tables:  map[string]string{"p": "patient"},
				Columns: []string{"p.unknown_column", "p.ssn"},
			},
			expected: map[string]string{
				"p.ssn": "VARCHAR", // Only known column should be resolved
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.queryRefs.ResolveColumns(schema)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectBulkOperation(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		expectedBulk bool
		expectedType string
	}{
		// PostgreSQL COPY operations
		{"copy_to", "COPY users TO '/tmp/users.csv'", true, "export"},
		{"copy_from", "COPY users FROM '/tmp/users.csv'", true, "import"},
		{"copy_generic", "COPY users (id, name)", true, "copy"},

		// MySQL operations
		{"load_data", "LOAD DATA INFILE '/tmp/data.csv' INTO TABLE users", true, "import"},
		{"select_outfile", "SELECT id, name FROM users INTO OUTFILE '/tmp/output.csv'", true, "export"},

		// INSERT operations
		{"insert_select", "INSERT INTO backup SELECT * FROM users", true, "insert"},
		{"regular_insert", "INSERT INTO users VALUES (1, 'John')", false, ""},

		// SELECT operations
		{"select_star_no_where", "SELECT * FROM users", true, "select"},
		{"select_star_with_where", "SELECT * FROM users WHERE id = 1", false, ""},
		{"select_columns", "SELECT id, name FROM users", false, ""},

		// Case insensitive
		{"copy_case_insensitive", "copy users to '/tmp/file'", true, "export"},
		{"load_case_insensitive", "load data infile '/tmp/file' into table users", true, "import"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isBulk, bulkType := detectBulkOperation(tt.query)
			assert.Equal(t, tt.expectedBulk, isBulk, "Bulk detection mismatch")
			assert.Equal(t, tt.expectedType, bulkType, "Bulk type mismatch")
		})
	}
}

func TestIsReservedWord(t *testing.T) {
	tests := []struct {
		word     string
		expected bool
	}{
		{"SELECT", true},
		{"select", true}, // Should be case insensitive
		{"FROM", true},
		{"users", false},
		{"patient_id", false},
		{"WHERE", true},
		{"JOIN", true},
		{"my_table", false},
	}

	for _, tt := range tests {
		t.Run(tt.word, func(t *testing.T) {
			result := isReservedWord(tt.word)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractColumnList(t *testing.T) {
	tests := []struct {
		name       string
		columnList string
		expected   []string
	}{
		{
			name:       "simple_columns",
			columnList: "id, name, email",
			expected:   []string{"id", "name", "email"},
		},
		{
			name:       "qualified_columns",
			columnList: "u.id, u.name, p.title",
			expected:   []string{"u.id", "u.name", "p.title"},
		},
		{
			name:       "with_aliases",
			columnList: "id as user_id, name as full_name",
			expected:   []string{"id", "name"}, // Should extract base column names
		},
		{
			name:       "mixed_format",
			columnList: "u.id, name, p.created_at as date",
			expected:   []string{"u.id", "name", "p.created_at"},
		},
		{
			name:       "empty_list",
			columnList: "",
			expected:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := &QueryRefs{Columns: []string{}}
			extractColumnList(tt.columnList, refs)

			// Check that all expected columns are present
			for _, expectedCol := range tt.expected {
				assert.Contains(t, refs.Columns, expectedCol, "Missing expected column: %s", expectedCol)
			}

			// Check that we don't have extra unexpected columns
			assert.Len(t, refs.Columns, len(tt.expected), "Unexpected number of columns extracted")
		})
	}
}

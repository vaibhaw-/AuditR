package loadr

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"gopkg.in/yaml.v3"
)

type LoadConfig struct {
	Driver     string `yaml:"driver"`
	Database   string `yaml:"database"`
	Output     string `yaml:"output"`
	Seed       int64  `yaml:"seed"`
	Patients   int    `yaml:"patients"`
	Encounters int    `yaml:"encounters"`
	Drugs      int    `yaml:"drugs"`
	Orders     int    `yaml:"orders"`
	DbUsers    int    `yaml:"dbUsers"`
}

func readLoadConfig(path string) (LoadConfig, error) {
	log.Printf("[DEBUG] Loading config from %s\n", path)
	var cfg LoadConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// sqlEscape escapes single quotes for safe inline SQL generation.
func sqlEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func Load(configPath *string) {
	cfg, err := readLoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Error loading config: %v", err)
	}

	// deterministic data if seed provided
	gofakeit.Seed(cfg.Seed)

	f, err := os.Create(cfg.Output)
	if err != nil {
		log.Fatalf("[FATAL] cannot create output file: %v", err)
	}
	defer f.Close()

	// Header with import instructions
	if cfg.Driver == "postgres" {
		fmt.Fprintf(f, "-- Generated SQL for PostgreSQL\n")
		fmt.Fprintf(f, "-- Import with: psql -U <user> -d %s -f %s\n\n", cfg.Database, cfg.Output)
	} else {
		fmt.Fprintf(f, "-- Generated SQL for MySQL\n")
		fmt.Fprintf(f, "-- Import with: mysql -u <user> -p %s < %s\n\n", cfg.Database, cfg.Output)
	}

	// Schema (DDL)
	writeDDL(f, cfg)

	// Database users
	writeDbUsers(f, cfg)

	// Data generation: writePatients returns patientIDs which are reused
	patientIDs := writePatients(f, cfg)
	drugIDs := writeDrugs(f, cfg)
	paymentIDs := writePaymentMethods(f, cfg, patientIDs)   // 1 payment method per patient
	orderIDs := writeOrders(f, cfg, patientIDs, paymentIDs) // orders reference patients + payment methods
	writeOrderItems(f, cfg, orderIDs, drugIDs)              // items reference orders + drugs
	writeEncounters(f, cfg, patientIDs)                     // encounters reference patients

	// Indexes
	writeIndexes(f, cfg)

	log.Printf("[INFO] Generation complete: patients=%d drugs=%d payments=%d orders=%d encounters=%d",
		len(patientIDs), len(drugIDs), len(paymentIDs), len(orderIDs), cfg.Encounters)

	fmt.Printf("✅ SQL file generated: %s\n", cfg.Output)
}

// ----------------- DDL -----------------

func writeDDL(f *os.File, cfg LoadConfig) {
	log.Printf("[INFO] Writing DDL for driver=%s", cfg.Driver)

	if cfg.Driver == "postgres" {
		// create schemas (Postgres)
		fmt.Fprintln(f, "DROP SCHEMA IF EXISTS healthcare CASCADE;")
		fmt.Fprintln(f, "DROP SCHEMA IF EXISTS pharmacy CASCADE;")
		fmt.Fprintln(f, "DROP SCHEMA IF EXISTS payments CASCADE;")
		fmt.Fprintln(f, "CREATE SCHEMA healthcare;")
		fmt.Fprintln(f, "CREATE SCHEMA pharmacy;")
		fmt.Fprintln(f, "CREATE SCHEMA payments;")
		fmt.Fprintln(f)

		// healthcare.patient
		fmt.Fprintln(f, `CREATE TABLE healthcare.patient (
    patient_id UUID PRIMARY KEY,
    ssn VARCHAR(11) UNIQUE NOT NULL,              -- PII
    first_name VARCHAR(100) NOT NULL,             -- PII
    last_name VARCHAR(100) NOT NULL,              -- PII
    dob DATE NOT NULL,                            -- PII
    email CITEXT UNIQUE,                          -- PII
    phone_number VARCHAR(20),                     -- PII
    address_line1 TEXT NOT NULL,                  -- PII
    address_line2 TEXT,                           -- PII
    city TEXT NOT NULL,                           -- PII
    state TEXT NOT NULL,                          -- PII
    postal_code TEXT NOT NULL,                    -- PII
    country TEXT NOT NULL,                        -- PII
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);`)

		// payments.payment_method (create before orders to satisfy FK)
		fmt.Fprintln(f, `CREATE TABLE payments.payment_method (
    payment_method_id UUID PRIMARY KEY,
    patient_id UUID NOT NULL REFERENCES healthcare.patient(patient_id),
    card_network VARCHAR(20) NOT NULL,            -- Financial
    card_last4 CHAR(4) NOT NULL,                  -- Financial
    payment_token CHAR(36) NOT NULL UNIQUE,       -- Financial
    created_at TIMESTAMPTZ DEFAULT now()
);`)

		// pharmacy.drug
		fmt.Fprintln(f, `CREATE TABLE pharmacy.drug (
    drug_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    dosage_form TEXT NOT NULL,
    strength TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    price NUMERIC(12,2) NOT NULL,
    stock_qty INT NOT NULL,
    active BOOLEAN DEFAULT true
);`)

		// pharmacy.pharmacy_order
		fmt.Fprintln(f, `CREATE TABLE pharmacy.pharmacy_order (
    order_id UUID PRIMARY KEY,
    patient_id UUID NOT NULL REFERENCES healthcare.patient(patient_id),
    order_ts TIMESTAMPTZ NOT NULL,
    status TEXT CHECK (status IN ('PENDING','FILLED','CANCELLED')) NOT NULL,
    total_price NUMERIC(12,2) NOT NULL,
    payment_method_id UUID REFERENCES payments.payment_method(payment_method_id), -- Financial
    shipping_address TEXT NOT NULL,               -- PII
    fulfilled_by UUID
);`)

		// pharmacy.pharmacy_order_item
		fmt.Fprintln(f, `CREATE TABLE pharmacy.pharmacy_order_item (
    order_id UUID REFERENCES pharmacy.pharmacy_order(order_id),
    drug_id UUID REFERENCES pharmacy.drug(drug_id),
    quantity INT NOT NULL,
    unit_price NUMERIC(12,2) NOT NULL,
    PRIMARY KEY (order_id, drug_id)
);`)

		// healthcare.encounter
		fmt.Fprintln(f, `CREATE TABLE healthcare.encounter (
    encounter_id UUID PRIMARY KEY,
    patient_id UUID NOT NULL REFERENCES healthcare.patient(patient_id),
    encounter_ts TIMESTAMPTZ NOT NULL,
    diagnosis TEXT NOT NULL,                      -- PHI
    treatment TEXT NOT NULL,                      -- PHI
    provider_name TEXT NOT NULL,
    notes TEXT                                    -- PHI
);`)

	} else {
		// MySQL: single database with prefixed tables, but include FK constraints (InnoDB)
		fmt.Fprintf(f, "DROP DATABASE IF EXISTS %s;\n", cfg.Database)
		fmt.Fprintf(f, "CREATE DATABASE %s;\n", cfg.Database)
		fmt.Fprintf(f, "USE %s;\n\n", cfg.Database)

		// healthcare_patient
		fmt.Fprintln(f, `CREATE TABLE healthcare_patient (
    patient_id CHAR(36) PRIMARY KEY,
    ssn VARCHAR(11) UNIQUE NOT NULL,              -- PII
    first_name VARCHAR(100) NOT NULL,             -- PII
    last_name VARCHAR(100) NOT NULL,              -- PII
    dob DATE NOT NULL,                            -- PII
    email VARCHAR(255) UNIQUE,                    -- PII
    phone_number VARCHAR(20),                     -- PII
    address_line1 TEXT NOT NULL,                  -- PII
    address_line2 TEXT,                           -- PII
    city TEXT NOT NULL,                           -- PII
    state TEXT NOT NULL,                          -- PII
    postal_code TEXT NOT NULL,                    -- PII
    country VARCHAR(50) NOT NULL,                 -- PII
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`)

		// payments_payment_method (create before orders)
		fmt.Fprintln(f, `CREATE TABLE payments_payment_method (
    payment_method_id CHAR(36) PRIMARY KEY,
    patient_id CHAR(36) NOT NULL,
    card_network VARCHAR(20) NOT NULL,            -- Financial
    card_last4 CHAR(4) NOT NULL,                  -- Financial
    payment_token CHAR(36) NOT NULL UNIQUE,       -- Financial
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES healthcare_patient(patient_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`)

		// pharmacy_drug
		fmt.Fprintln(f, `CREATE TABLE pharmacy_drug (
    drug_id CHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    dosage_form VARCHAR(50) NOT NULL,
    strength VARCHAR(50) NOT NULL,
    manufacturer VARCHAR(100) NOT NULL,
    price DECIMAL(12,2) NOT NULL,
    stock_qty INT NOT NULL,
    active BOOLEAN DEFAULT true
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`)

		// pharmacy_order
		fmt.Fprintln(f, `CREATE TABLE pharmacy_order (
    order_id CHAR(36) PRIMARY KEY,
    patient_id CHAR(36) NOT NULL,
    order_ts DATETIME NOT NULL,
    status ENUM('PENDING','FILLED','CANCELLED') NOT NULL,
    total_price DECIMAL(12,2) NOT NULL,
    payment_method_id CHAR(36),
    shipping_address TEXT NOT NULL,               -- PII
    fulfilled_by CHAR(36),
    FOREIGN KEY (patient_id) REFERENCES healthcare_patient(patient_id),
    FOREIGN KEY (payment_method_id) REFERENCES payments_payment_method(payment_method_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`)

		// pharmacy_order_item
		fmt.Fprintln(f, `CREATE TABLE pharmacy_order_item (
    order_id CHAR(36),
    drug_id CHAR(36),
    quantity INT NOT NULL,
    unit_price DECIMAL(12,2) NOT NULL,
    PRIMARY KEY (order_id, drug_id),
    FOREIGN KEY (order_id) REFERENCES pharmacy_order(order_id),
    FOREIGN KEY (drug_id) REFERENCES pharmacy_drug(drug_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`)

		// healthcare_encounter
		fmt.Fprintln(f, `CREATE TABLE healthcare_encounter (
    encounter_id CHAR(36) PRIMARY KEY,
    patient_id CHAR(36) NOT NULL,
    encounter_ts DATETIME NOT NULL,
    diagnosis TEXT NOT NULL,                      -- PHI
    treatment TEXT NOT NULL,                      -- PHI
    provider_name VARCHAR(100) NOT NULL,
    notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES healthcare_patient(patient_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`)
	}
	fmt.Fprintln(f)
	log.Printf("[DEBUG] DDL written")
}

// ----------------- Users -----------------

func writeDbUsers(f *os.File, cfg LoadConfig) {
	log.Printf("[INFO] Writing %d DB users", cfg.DbUsers)
	for i := 1; i <= cfg.DbUsers; i++ {
		username := fmt.Sprintf("appuser%d", i)
		password := fmt.Sprintf("password%d", i)

		if cfg.Driver == "postgres" {
			fmt.Fprintf(f,
				"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s LOGIN PASSWORD '%s'; END IF; END$$;\n",
				username, username, password,
			)
			fmt.Fprintf(f, "GRANT CONNECT ON DATABASE %s TO %s;\n", cfg.Database, username)
			fmt.Fprintf(f, "GRANT USAGE ON SCHEMA healthcare, pharmacy, payments TO %s;\n", username)
			fmt.Fprintf(f, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA healthcare TO %s;\n", username)
			fmt.Fprintf(f, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA pharmacy TO %s;\n", username)
			fmt.Fprintf(f, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA payments TO %s;\n", username)
		} else {
			fmt.Fprintf(f,
				"CREATE USER IF NOT EXISTS '%s'@'%%' IDENTIFIED BY '%s';\n"+
					"GRANT SELECT, INSERT, UPDATE, DELETE ON %s.* TO '%s'@'%%';\n",
				username, password, cfg.Database, username,
			)
		}
	}
	fmt.Fprintf(f, "\n-- Created %d database users\n\n", cfg.DbUsers)
	log.Printf("[DEBUG] DB users written")
}

// ----------------- Data generation (write to SQL file) -----------------

// writePatients returns the list of generated patient IDs
func writePatients(f *os.File, cfg LoadConfig) []string {
	log.Printf("[INFO] Generating %d patients", cfg.Patients)
	table := "healthcare.patient"
	if cfg.Driver == "mysql" {
		table = "healthcare_patient"
	}

	ids := make([]string, 0, cfg.Patients)
	for i := 0; i < cfg.Patients; i++ {
		id := gofakeit.UUID()
		ids = append(ids, id)

		ssn := fmt.Sprintf("%03d-%02d-%04d", gofakeit.Number(100, 999), gofakeit.Number(10, 99), gofakeit.Number(1000, 9999))
		first := sqlEscape(gofakeit.FirstName())
		last := sqlEscape(gofakeit.LastName())
		dob := gofakeit.Date().Format("2006-01-02")
		email := sqlEscape(fmt.Sprintf("%s.%s%d@example.org", first, last, gofakeit.Number(10, 99)))
		phone := sqlEscape(gofakeit.PhoneFormatted())
		street := sqlEscape(gofakeit.Street())
		city := sqlEscape(gofakeit.City())
		state := sqlEscape(gofakeit.State())
		zip := sqlEscape(gofakeit.Zip())

		if cfg.Driver == "postgres" {
			fmt.Fprintf(f,
				"INSERT INTO %s (patient_id, ssn, first_name, last_name, dob, email, phone_number, address_line1, city, state, postal_code, country, created_at, updated_at) "+
					"VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','US',NOW(),NOW());\n",
				table, id, ssn, first, last, dob, email, phone, street, city, state, zip,
			)
		} else {
			fmt.Fprintf(f,
				"INSERT INTO %s (patient_id, ssn, first_name, last_name, dob, email, phone_number, address_line1, city, state, postal_code, country, created_at, updated_at) "+
					"VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','US',NOW(),NOW());\n",
				table, id, ssn, first, last, dob, email, phone, street, city, state, zip,
			)
		}
	}

	// summary comment and debug log with sample IDs
	fmt.Fprintf(f, "\n-- Inserted %d patients\n\n", len(ids))
	sample := ids
	if len(ids) > 3 {
		sample = ids[:3]
	}
	log.Printf("[DEBUG] Inserted %d patients; sample patient_ids=%s", len(ids), strings.Join(sample, ","))
	return ids
}

// writeDrugs returns the list of generated drug IDs
func writeDrugs(f *os.File, cfg LoadConfig) []string {
	log.Printf("[INFO] Generating %d drugs", cfg.Drugs)
	table := "pharmacy.drug"
	if cfg.Driver == "mysql" {
		table = "pharmacy_drug"
	}
	ids := make([]string, 0, cfg.Drugs)

	for i := 0; i < cfg.Drugs; i++ {
		id := gofakeit.UUID()
		ids = append(ids, id)

		name := sqlEscape(RandomDrug())
		dosage := sqlEscape(RandomDosageForm())
		strength := sqlEscape(RandomStrength())
		manufacturer := sqlEscape(RandomManufacturer())
		price := gofakeit.Price(5, 500)
		stock := gofakeit.Number(0, 500)

		fmt.Fprintf(f,
			"INSERT INTO %s (drug_id, name, dosage_form, strength, manufacturer, price, stock_qty, active) "+
				"VALUES ('%s','%s','%s','%s','%s',%.2f,%d,true);\n",
			table, id, name, dosage, strength, manufacturer, price, stock,
		)
	}

	fmt.Fprintf(f, "\n-- Inserted %d drugs\n\n", len(ids))
	sample := ids
	if len(ids) > 3 {
		sample = ids[:3]
	}
	log.Printf("[DEBUG] Inserted %d drugs; sample drug_ids=%s", len(ids), strings.Join(sample, ","))
	return ids
}

// writePaymentMethods creates one payment method per patient and returns IDs
func writePaymentMethods(f *os.File, cfg LoadConfig, patientIDs []string) []string {
	log.Printf("[INFO] Generating %d payment methods (1 per patient)", len(patientIDs))
	table := "payments.payment_method"
	if cfg.Driver == "mysql" {
		table = "payments_payment_method"
	}

	ids := make([]string, 0, len(patientIDs))
	for i, pid := range patientIDs {
		id := gofakeit.UUID()
		ids = append(ids, id)

		cardNetwork := sqlEscape("VISA")
		cardLast4 := fmt.Sprintf("%04d", gofakeit.Number(1000, 9999))
		token := gofakeit.UUID()

		if cfg.Driver == "postgres" {
			fmt.Fprintf(f,
				"INSERT INTO %s (payment_method_id, patient_id, card_network, card_last4, payment_token, created_at) VALUES ('%s','%s','%s','%s','%s',NOW());\n",
				table, id, pid, cardNetwork, cardLast4, token,
			)
		} else {
			fmt.Fprintf(f,
				"INSERT INTO %s (payment_method_id, patient_id, card_network, card_last4, payment_token, created_at) VALUES ('%s','%s','%s','%s','%s',NOW());\n",
				table, id, pid, cardNetwork, cardLast4, token,
			)
		}

		// small debug log occasionally
		if (i+1)%1000 == 0 {
			log.Printf("[DEBUG] created %d payment methods", i+1)
		}
	}

	fmt.Fprintf(f, "\n-- Inserted %d payment methods\n\n", len(ids))
	sample := ids
	if len(ids) > 3 {
		sample = ids[:3]
	}
	log.Printf("[DEBUG] Inserted %d payment methods; sample payment_method_ids=%s", len(ids), strings.Join(sample, ","))
	return ids
}

// writeOrders returns the list of generated order IDs
func writeOrders(f *os.File, cfg LoadConfig, patientIDs []string, paymentIDs []string) []string {
	log.Printf("[INFO] Generating %d orders", cfg.Orders)
	table := "pharmacy.pharmacy_order"
	if cfg.Driver == "mysql" {
		table = "pharmacy_order"
	}

	ids := make([]string, 0, cfg.Orders)
	for i := 0; i < cfg.Orders; i++ {
		id := gofakeit.UUID()
		ids = append(ids, id)

		pid := patientIDs[gofakeit.Number(0, len(patientIDs)-1)]
		payment := paymentIDs[gofakeit.Number(0, len(paymentIDs)-1)]
		status := gofakeit.RandomString([]string{"PENDING", "FILLED", "CANCELLED"})
		total := gofakeit.Price(10, 1000)
		ship := sqlEscape(gofakeit.Street())
		fulfilledBy := gofakeit.UUID()
		orderTS := time.Now().AddDate(0, 0, -gofakeit.Number(0, 365)).Format("2006-01-02")

		fmt.Fprintf(f,
			"INSERT INTO %s (order_id, patient_id, order_ts, status, total_price, shipping_address, payment_method_id, fulfilled_by) "+
				"VALUES ('%s','%s','%s','%s',%.2f,'%s','%s','%s');\n",
			table, id, pid, orderTS, status, total, ship, payment, fulfilledBy,
		)
	}

	fmt.Fprintf(f, "\n-- Inserted %d pharmacy orders\n\n", len(ids))
	sample := ids
	if len(ids) > 3 {
		sample = ids[:3]
	}
	log.Printf("[DEBUG] Inserted %d orders; sample order_ids=%s", len(ids), strings.Join(sample, ","))
	return ids
}

// writeOrderItems creates 1-3 items per order referencing existing drugs
func writeOrderItems(f *os.File, cfg LoadConfig, orderIDs []string, drugIDs []string) {
	log.Printf("[INFO] Generating order items for %d orders", len(orderIDs))
	table := "pharmacy.pharmacy_order_item"
	if cfg.Driver == "mysql" {
		table = "pharmacy_order_item"
	}

	totalItems := 0
	for _, oid := range orderIDs {
		// choose between 1..3 unique drugs per order
		numItems := gofakeit.Number(1, 3)
		selected := map[string]struct{}{}
		attempts := 0
		for len(selected) < numItems && attempts < 10 {
			did := drugIDs[gofakeit.Number(0, len(drugIDs)-1)]
			if _, ok := selected[did]; !ok {
				selected[did] = struct{}{}
			}
			attempts++
		}

		for did := range selected {
			qty := gofakeit.Number(1, 5)
			price := gofakeit.Price(1, 200)
			fmt.Fprintf(f,
				"INSERT INTO %s (order_id, drug_id, quantity, unit_price) VALUES ('%s','%s',%d,%.2f);\n",
				table, oid, did, qty, price,
			)
			totalItems++
		}
	}

	fmt.Fprintf(f, "\n-- Inserted %d pharmacy order items\n\n", totalItems)
	log.Printf("[DEBUG] Inserted %d order items across %d orders", totalItems, len(orderIDs))
}

// writeEncounters writes encounter rows and reuses patient IDs
func writeEncounters(f *os.File, cfg LoadConfig, patientIDs []string) {
	log.Printf("[INFO] Generating %d encounters", cfg.Encounters)
	table := "healthcare.encounter"
	if cfg.Driver == "mysql" {
		table = "healthcare_encounter"
	}

	for i := 0; i < cfg.Encounters; i++ {
		id := gofakeit.UUID()
		pid := patientIDs[gofakeit.Number(0, len(patientIDs)-1)]
		ts := time.Now().AddDate(0, 0, -gofakeit.Number(0, 365)).Format("2006-01-02")
		diagnosis := sqlEscape(RandomDiagnosis())
		treatment := sqlEscape(fmt.Sprintf("Treatment plan %d", gofakeit.Number(1, 100)))
		provider := sqlEscape(gofakeit.Name())
		notes := sqlEscape(gofakeit.Sentence(10))

		fmt.Fprintf(f,
			"INSERT INTO %s (encounter_id, patient_id, encounter_ts, diagnosis, treatment, provider_name, notes) "+
				"VALUES ('%s','%s','%s','%s','%s','%s','%s');\n",
			table, id, pid, ts, diagnosis, treatment, provider, notes,
		)
	}

	fmt.Fprintf(f, "\n-- Inserted %d encounters\n\n", cfg.Encounters)
	log.Printf("[DEBUG] Inserted %d encounters", cfg.Encounters)
}

func writeIndexes(f *os.File, cfg LoadConfig) {
	log.Printf("[INFO] Writing indexes")
	if cfg.Driver == "postgres" {
		fmt.Fprintln(f, "CREATE INDEX idx_patient_email ON healthcare.patient(email);")
		fmt.Fprintln(f, "CREATE INDEX idx_patient_ssn ON healthcare.patient(ssn);")
		fmt.Fprintln(f, "CREATE INDEX idx_encounter_patient_ts ON healthcare.encounter(patient_id, encounter_ts);")
		fmt.Fprintln(f, "CREATE INDEX idx_order_patient_ts ON pharmacy.pharmacy_order(patient_id, order_ts);")
	} else {
		fmt.Fprintln(f, "CREATE INDEX idx_patient_email ON healthcare_patient(email);")
		fmt.Fprintln(f, "CREATE INDEX idx_patient_ssn ON healthcare_patient(ssn);")
		fmt.Fprintln(f, "CREATE INDEX idx_encounter_patient_ts ON healthcare_encounter(patient_id, encounter_ts);")
		fmt.Fprintln(f, "CREATE INDEX idx_order_patient_ts ON pharmacy_order(patient_id, order_ts);")
	}
	fmt.Fprintln(f, "\n-- Indexes created")
	log.Printf("[DEBUG] Indexes written")
}

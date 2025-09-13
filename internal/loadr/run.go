package loadr

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"gopkg.in/yaml.v3"
)

// ------------------- Config -------------------

// RunConfig describes the workload configuration parsed from YAML
type RunConfig struct {
	Driver   string `yaml:"driver"`
	Database string `yaml:"database"`
	Users    []struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"users"`
	Seed        int64  `yaml:"seed"`
	RunId       string `yaml:"runId"`
	Concurrency int    `yaml:"concurrency"`
	TotalOps    int    `yaml:"totalOps"`

	Mix struct {
		Select float64 `yaml:"select"`
		Update float64 `yaml:"update"`
	} `yaml:"mix"`

	Sensitivity struct {
		SensitiveOnly    float64 `yaml:"sensitive_only"`
		Mixed            float64 `yaml:"mixed"`
		NonSensitiveOnly float64 `yaml:"non_sensitive_only"`
	} `yaml:"sensitivity"`

	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// ------------------- Preload Cache -------------------

// preloadCache holds IDs preloaded from DB to avoid empty queries
type preloadCache struct {
	PatientIDs       []string
	OrderIDs         []string
	DrugIDs          []string
	PaymentMethodIDs []string
	EncounterIDs     []string
}

// ------------------- Entry Point -------------------

// readRunConfig parses the YAML workload config
func readRunConfig(path string) (RunConfig, error) {
	var cfg RunConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Run executes the workload simulation
func Run(configPath *string) {
	cfg, err := readRunConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] error loading run config: %v", err)
	}

	// Defaults
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		if cfg.Driver == "postgres" {
			cfg.Port = 5432
		} else {
			cfg.Port = 3306
		}
	}

	// Seed RNG for reproducibility
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rand.Seed(seed)

	log.Printf("[INFO] Starting run=%s driver=%s db=%s ops=%d concurrency=%d seed=%d",
		cfg.RunId, cfg.Driver, cfg.Database, cfg.TotalOps, cfg.Concurrency, seed)

	normalizeMixes(&cfg)

	// Preload IDs from the database to ensure queries always hit real rows.
	// This avoids empty SELECTs or failing UPDATEs.
	// Preload IDs using first DB user
	first := cfg.Users[0]
	dsn := buildDSN(cfg.Driver, first.Username, first.Password, cfg.Host, cfg.Port, cfg.Database)
	db, err := sql.Open(cfg.Driver, dsn)
	if err != nil {
		log.Fatalf("[FATAL] preload connect failed: %v", err)
	}
	defer db.Close()
	cache := preloadAllIDs(db, cfg.Driver)
	log.Printf("[INFO] Preloaded: patients=%d orders=%d drugs=%d payments=%d encounters=%d",
		len(cache.PatientIDs), len(cache.OrderIDs), len(cache.DrugIDs), len(cache.PaymentMethodIDs), len(cache.EncounterIDs))

	// Create operation channel for workers
	var wg sync.WaitGroup
	opsCh := make(chan int, cfg.TotalOps)
	for i := 0; i < cfg.TotalOps; i++ {
		opsCh <- i
	}
	close(opsCh)

	// Stats
	stats := map[string]int{"select": 0, "update": 0, "errors": 0}
	var statsMu sync.Mutex

	// Start workers
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			// NOTE: Each worker connects once using a random appuser.
			// This means all queries from that worker appear under the same user,
			// rather than switching users per query (simplifies connection handling).
			user := cfg.Users[rand.Intn(len(cfg.Users))]
			dsn := buildDSN(cfg.Driver, user.Username, user.Password, cfg.Host, cfg.Port, cfg.Database)
			dbw, err := sql.Open(cfg.Driver, dsn)
			if err != nil {
				log.Printf("[ERROR] worker %d: connect failed: %v", workerID, err)
				return
			}
			defer dbw.Close()
			log.Printf("[DEBUG] Worker %d connected as %s", workerID, user.Username)

			for range opsCh {
				op := pickOpType(cfg)
				sens := pickSensitivity(cfg)
				query, args := generateQuery(cfg, op, sens, user.Username, cache)
				if query == "" {
					continue
				}

				log.Printf("[DEBUG] Worker %d preparing %s %s", workerID, op, sens)

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := dbw.ExecContext(ctx, query, args...)
				cancel()
				if err != nil {
					log.Printf("[ERROR] worker %d: exec failed: %v | q=%s args=%v", workerID, err, query, args)
					statsMu.Lock()
					stats["errors"]++
					statsMu.Unlock()
				} else {
					statsMu.Lock()
					stats[strings.ToLower(op)]++
					statsMu.Unlock()
				}
			}
			log.Printf("[DEBUG] Worker %d finished", workerID)
		}(w)
	}
	wg.Wait()

	log.Printf("[INFO] Run complete: select=%d update=%d errors=%d",
		stats["select"], stats["update"], stats["errors"])
}

// ------------------- Helpers -------------------

// buildDSN constructs a DSN for postgres/mysql
func buildDSN(driver, user, pass, host string, port int, db string) string {
	if driver == "postgres" {
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, pass, host, port, db)
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&multiStatements=true", user, pass, host, port, db)
}

// normalizeMixes ensures operation and sensitivity ratios sum to 1.0
func normalizeMixes(cfg *RunConfig) {
	// op mix
	tot := cfg.Mix.Select + cfg.Mix.Update
	if tot <= 0 {
		cfg.Mix.Select, cfg.Mix.Update = 0.7, 0.3
		tot = 1
	}
	cfg.Mix.Select /= tot
	cfg.Mix.Update /= tot

	// sensitivity mix
	tots := cfg.Sensitivity.SensitiveOnly + cfg.Sensitivity.Mixed + cfg.Sensitivity.NonSensitiveOnly
	if tots <= 0 {
		cfg.Sensitivity.SensitiveOnly, cfg.Sensitivity.Mixed, cfg.Sensitivity.NonSensitiveOnly = 0.4, 0.4, 0.2
		tots = 1
	}
	cfg.Sensitivity.SensitiveOnly /= tots
	cfg.Sensitivity.Mixed /= tots
	cfg.Sensitivity.NonSensitiveOnly /= tots
}

func pickOpType(cfg RunConfig) string {
	if rand.Float64() < cfg.Mix.Select {
		return "SELECT"
	}
	return "UPDATE"
}

func pickSensitivity(cfg RunConfig) string {
	p := rand.Float64()
	if p < cfg.Sensitivity.SensitiveOnly {
		return "sensitive_only"
	}
	p -= cfg.Sensitivity.SensitiveOnly
	if p < cfg.Sensitivity.Mixed {
		return "mixed"
	}
	return "non_sensitive_only"
}

// ------------------- Preloading IDs -------------------

// preloadAllIDs loads IDs from the database into memory
func preloadAllIDs(db *sql.DB, driver string) preloadCache {
	cache := preloadCache{}

	query := func(q string, dest *[]string, label string) {
		rows, err := db.Query(q)
		if err != nil {
			log.Printf("[ERROR] preload %s failed: %v", label, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				*dest = append(*dest, id)
			}
		}
		log.Printf("[DEBUG] Preloaded %d %s", len(*dest), label)
	}

	if driver == "postgres" {
		query("SELECT patient_id FROM healthcare.patient", &cache.PatientIDs, "patients")
		query("SELECT order_id FROM pharmacy.pharmacy_order", &cache.OrderIDs, "orders")
		query("SELECT drug_id FROM pharmacy.drug", &cache.DrugIDs, "drugs")
		query("SELECT payment_method_id FROM payments.payment_method", &cache.PaymentMethodIDs, "payments")
		query("SELECT encounter_id FROM healthcare.encounter", &cache.EncounterIDs, "encounters")
	} else {
		query("SELECT patient_id FROM healthcare_patient", &cache.PatientIDs, "patients")
		query("SELECT order_id FROM pharmacy_order", &cache.OrderIDs, "orders")
		query("SELECT drug_id FROM pharmacy_drug", &cache.DrugIDs, "drugs")
		query("SELECT payment_method_id FROM payments_payment_method", &cache.PaymentMethodIDs, "payments")
		query("SELECT encounter_id FROM healthcare_encounter", &cache.EncounterIDs, "encounters")
	}
	return cache
}

// ------------------- Query Generation -------------------

// generateQuery builds a query string + args for given op + sensitivity
func generateQuery(cfg RunConfig, op string, sensitivity string, username string, cache preloadCache) (string, []interface{}) {
	ts := time.Now().UTC().Format(time.RFC3339)
	comment := fmt.Sprintf("/* run_id=%s op=%s sensitivity=%s user=%s ts=%s */ ",
		cfg.RunId, strings.ToLower(op), sensitivity, username, ts)

	// placeholders
	ph := func(i int) string {
		if cfg.Driver == "postgres" {
			return fmt.Sprintf("$%d", i)
		}
		return "?"
	}

	// SELECT sensitive_only: returns PII + Financial data (e.g., SSN, card info)
	// UPDATE mixed: modifies Financial + business fields (e.g., order total, status)
	// Non-sensitive queries only touch non-PII/PHI tables (e.g., drugs, stock).

	// --- SELECT queries ---
	if op == "SELECT" {
		switch sensitivity {
		case "sensitive_only":
			if len(cache.PatientIDs) == 0 || len(cache.PaymentMethodIDs) == 0 {
				return "", nil
			}
			log.Printf("[DEBUG] Generating sensitive SELECT")
			q := comment + "SELECT p.patient_id, p.ssn, p.email, pm.card_last4 " +
				"FROM healthcare.patient p " +
				"JOIN payments.payment_method pm ON p.patient_id = pm.patient_id " +
				"WHERE p.patient_id = " + ph(1) + " LIMIT 5"
			if cfg.Driver == "mysql" {
				q = strings.ReplaceAll(q, "healthcare.patient", "healthcare_patient")
				q = strings.ReplaceAll(q, "payments.payment_method", "payments_payment_method")
			}
			return q, []interface{}{cache.PatientIDs[rand.Intn(len(cache.PatientIDs))]}

		case "mixed":
			if len(cache.PatientIDs) == 0 {
				return "", nil
			}
			log.Printf("[DEBUG] Generating mixed SELECT")
			q := comment + "SELECT p.email, e.diagnosis, o.total_price, pm.card_last4 " +
				"FROM healthcare.patient p " +
				"JOIN healthcare.encounter e ON p.patient_id = e.patient_id " +
				"JOIN pharmacy.pharmacy_order o ON p.patient_id = o.patient_id " +
				"JOIN payments.payment_method pm ON p.patient_id = pm.patient_id " +
				"WHERE p.patient_id = " + ph(1) + " LIMIT 5"
			if cfg.Driver == "mysql" {
				q = strings.ReplaceAll(q, "healthcare.patient", "healthcare_patient")
				q = strings.ReplaceAll(q, "healthcare.encounter", "healthcare_encounter")
				q = strings.ReplaceAll(q, "pharmacy.pharmacy_order", "pharmacy_order")
				q = strings.ReplaceAll(q, "payments.payment_method", "payments_payment_method")
			}
			return q, []interface{}{cache.PatientIDs[rand.Intn(len(cache.PatientIDs))]}

		default: // non_sensitive_only
			if len(cache.DrugIDs) == 0 {
				return "", nil
			}
			log.Printf("[DEBUG] Generating non-sensitive SELECT")
			q := comment + "SELECT drug_id, name, price, stock_qty " +
				"FROM pharmacy.drug WHERE drug_id = " + ph(1)
			if cfg.Driver == "mysql" {
				q = strings.ReplaceAll(q, "pharmacy.drug", "pharmacy_drug")
			}
			return q, []interface{}{cache.DrugIDs[rand.Intn(len(cache.DrugIDs))]}
		}
	}

	// --- UPDATE queries ---
	if op == "UPDATE" {
		switch sensitivity {
		case "sensitive_only":
			if len(cache.PatientIDs) == 0 {
				return "", nil
			}
			log.Printf("[DEBUG] Generating sensitive UPDATE")
			newPhone := fmt.Sprintf("+1-%03d-%03d-%04d", rand.Intn(900)+100, rand.Intn(900), rand.Intn(10000))
			q := comment + "UPDATE healthcare.patient SET phone_number=" + ph(1) + " WHERE patient_id=" + ph(2)
			if cfg.Driver == "mysql" {
				q = strings.ReplaceAll(q, "healthcare.patient", "healthcare_patient")
			}
			return q, []interface{}{newPhone, cache.PatientIDs[rand.Intn(len(cache.PatientIDs))]}

		case "mixed":
			if len(cache.OrderIDs) == 0 {
				return "", nil
			}
			log.Printf("[DEBUG] Generating mixed UPDATE")
			newStatus := []string{"PENDING", "FILLED", "CANCELLED"}[rand.Intn(3)]
			newTotal := rand.Float64() * 100
			q := comment + "UPDATE pharmacy.pharmacy_order SET status=" + ph(1) + ", total_price=" + ph(2) + " WHERE order_id=" + ph(3)
			if cfg.Driver == "mysql" {
				q = strings.ReplaceAll(q, "pharmacy.pharmacy_order", "pharmacy_order")
			}
			return q, []interface{}{newStatus, newTotal, cache.OrderIDs[rand.Intn(len(cache.OrderIDs))]}

		default: // non_sensitive_only
			if len(cache.DrugIDs) == 0 {
				return "", nil
			}
			log.Printf("[DEBUG] Generating non-sensitive UPDATE")
			newStock := rand.Intn(500)
			q := comment + "UPDATE pharmacy.drug SET stock_qty=" + ph(1) + " WHERE drug_id=" + ph(2)
			if cfg.Driver == "mysql" {
				q = strings.ReplaceAll(q, "pharmacy.drug", "pharmacy_drug")
			}
			return q, []interface{}{newStock, cache.DrugIDs[rand.Intn(len(cache.DrugIDs))]}
		}
	}

	return "", nil
}

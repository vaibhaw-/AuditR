-- ----------------------------------------------------------------------------
-- Verification script for PostgreSQL seed data (practicumdb)
-- Run with:
--   psql -U <user> -d practicumdb -f verify_pg.sql
-- ----------------------------------------------------------------------------

-- Switch to practicumdb
\c practicumdb

-- 1. Schemas
\dn

-- 2. Tables per schema
\dt healthcare.*
\dt pharmacy.*
\dt payments.*

-- 3. Row counts
SELECT 'patients' AS table, COUNT(*) FROM healthcare.patient;
SELECT 'encounters' AS table, COUNT(*) FROM healthcare.encounter;
SELECT 'drugs' AS table, COUNT(*) FROM pharmacy.drug;
SELECT 'orders' AS table, COUNT(*) FROM pharmacy.pharmacy_order;
SELECT 'order_items' AS table, COUNT(*) FROM pharmacy.pharmacy_order_item;
SELECT 'payment_methods' AS table, COUNT(*) FROM payments.payment_method;

-- 4. Sample joins
SELECT e.encounter_id, e.patient_id, p.email, e.diagnosis
FROM healthcare.encounter e
JOIN healthcare.patient p ON e.patient_id = p.patient_id
LIMIT 5;

SELECT o.order_id, o.patient_id, o.total_price, pm.card_last4
FROM pharmacy.pharmacy_order o
JOIN payments.payment_method pm ON o.payment_method_id = pm.payment_method_id
LIMIT 5;

SELECT oi.order_id, oi.drug_id, d.name, oi.quantity
FROM pharmacy.pharmacy_order_item oi
JOIN pharmacy.drug d ON oi.drug_id = d.drug_id
LIMIT 5;

-- 5. Indexes
SELECT indexname, tablename FROM pg_indexes WHERE schemaname IN ('healthcare','pharmacy','payments');

-- 6. Users
\du
SELECT rolname FROM pg_roles WHERE rolname LIKE 'appuser%';

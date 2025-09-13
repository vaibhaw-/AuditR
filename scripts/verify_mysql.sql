-- ----------------------------------------------------------------------------
-- Verification script for MySQL seed data (practicumdb)
-- Run with:
--   mysql -u <user> -p practicumdb < verify_mysql.sql
-- ----------------------------------------------------------------------------

USE practicumdb;

-- 1. Tables
SHOW TABLES;

-- 2. Row counts
SELECT 'patients' AS table_name, COUNT(*) FROM healthcare_patient;
SELECT 'encounters' AS table_name, COUNT(*) FROM healthcare_encounter;
SELECT 'drugs' AS table_name, COUNT(*) FROM pharmacy_drug;
SELECT 'orders' AS table_name, COUNT(*) FROM pharmacy_order;
SELECT 'order_items' AS table_name, COUNT(*) FROM pharmacy_order_item;
SELECT 'payment_methods' AS table_name, COUNT(*) FROM payments_payment_method;

-- 3. Sample joins
SELECT e.encounter_id, e.patient_id, p.email, e.diagnosis
FROM healthcare_encounter e
JOIN healthcare_patient p ON e.patient_id = p.patient_id
LIMIT 5;

SELECT o.order_id, o.patient_id, o.total_price, pm.card_last4
FROM pharmacy_order o
JOIN payments_payment_method pm ON o.payment_method_id = pm.payment_method_id
LIMIT 5;

SELECT oi.order_id, oi.drug_id, d.name, oi.quantity
FROM pharmacy_order_item oi
JOIN pharmacy_drug d ON oi.drug_id = d.drug_id
LIMIT 5;

-- 4. Indexes
SHOW INDEXES FROM healthcare_patient;
SHOW INDEXES FROM healthcare_encounter;
SHOW INDEXES FROM pharmacy_order;

-- 5. Users
SELECT user, host FROM mysql.user WHERE user LIKE 'appuser%';
SHOW GRANTS FOR 'appuser1'@'%';

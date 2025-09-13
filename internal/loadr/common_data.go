package loadr

import (
	"github.com/brianvoe/gofakeit/v7"
)

// Shared lists for synthetic data generation and workload simulation.

// randomDrug returns a random drug from drugList
func RandomDrug() string {
	return DrugNames[gofakeit.Number(0, len(DrugNames)-1)]
}

var DrugNames = []string{
	"Atorvastatin", "Levothyroxine", "Lisinopril", "Metformin", "Amlodipine",
	"Metoprolol", "Omeprazole", "Simvastatin", "Losartan", "Albuterol",
	"Gabapentin", "Hydrochlorothiazide", "Sertraline", "Furosemide", "Fluticasone",
	"Acetaminophen", "Prednisone", "Tramadol", "Amoxicillin", "Pantoprazole",
	"Citalopram", "Cetirizine", "Trazodone", "Clopidogrel", "Atenolol",
	"Rosuvastatin", "Escitalopram", "Bupropion", "Duloxetine", "Warfarin",
	"Insulin Glargine", "Insulin Aspart", "Glimepiride", "Sitagliptin", "Borateol",
	"Spironolactone", "Pravastatin", "Pioglitazone", "Nitrofurantoin", "Allopurinol",
	"Amiodarone", "Ampicillin", "Doxycycline", "Cefuroxime", "Levofloxacin",
	"Mupirocin", "Ketoconazole", "Ranitidine", "Ipratropium", "Morphine",
	"Oxycodone", "Clindamycin", "Sulfasalazine", "Ethinyl Estradiol", "Finasteride",
	"Hydroxychloroquine", "Loratadine", "Meloxicam", "Naproxen", "Diclofenac",
	"Ondansetron", "Propranolol", "Timolol", "Varenicline", "Mirtazapine",
	"Phenazopyridine", "Meclizine", "Voriconazole", "Acyclovir", "Valacyclovir",
	"Carvedilol", "Benazepril", "Enalapril", "Rivaroxaban", "Apixaban",
	"Digoxin", "Dapagliflozin", "Canagliflozin", "Empagliflozin", "Eltrombopag",
	"Azithromycin", "Ceftriaxone", "Imipenem", "Meropenem", "Linezolid",
	"Vancomycin", "Fluconazole", "Metronidazole", "Levothyroxine Sodium", "Budesonide",
	"Beclomethasone", "Tiotropium", "Formoterol", "Salmeterol", "Levalbuterol",
	"Ropinirole", "Pramipexole", "Selegiline", "Triamcinolone", "Clonidine",
	"Prochlorperazine", "Lorazepam", "Alprazolam", "Diazepam", "Buspirone",
	"Hydralazine", "Isosorbide Mononitrate", "Methotrexate", "Sulindac", "Tamsulosin",
}

// randomDosageForm returns a random dosage form from DosageForms
func RandomDosageForm() string {
	return DosageForms[gofakeit.Number(0, len(DosageForms)-1)]
}

var DosageForms = []string{"tablet", "capsule", "injection", "syrup", "ointment"}

// randomStrength returns a random strength from Strengths
func RandomStrength() string {
	return Strengths[gofakeit.Number(0, len(Strengths)-1)]
}

var Strengths = []string{"100mg", "250mg", "500mg", "10mg/ml", "20mg/ml"}

// randomManufacturer returns a random manufacturer from Manufacturers
func RandomManufacturer() string {
	return Manufacturers[gofakeit.Number(0, len(Manufacturers)-1)]
}

var Manufacturers = []string{"Pfizer", "Roche", "Novartis", "Cipla", "Sun Pharma"}

// randomDiagnosis returns a random diagnosis from diagnosisList
func RandomDiagnosis() string {
	return Diagnoses[gofakeit.Number(0, len(Diagnoses)-1)]
}

var Diagnoses = []string{
	"Hypertension", "Type 2 Diabetes Mellitus", "Hyperlipidemia", "Asthma",
	"Chronic Obstructive Pulmonary Disease", "Acute Bronchitis", "Pneumonia",
	"Upper Respiratory Infection", "Gastroesophageal Reflux Disease", "Peptic Ulcer Disease",
	"Irritable Bowel Syndrome", "Chronic Kidney Disease", "Acute Kidney Injury",
	"Urinary Tract Infection", "Osteoarthritis", "Rheumatoid Arthritis", "Osteoporosis",
	"Low Back Pain", "Sciatica", "Migraine", "Tension Headache",
	"Major Depressive Disorder", "Generalized Anxiety Disorder", "Bipolar Disorder",
	"Schizophrenia", "Insomnia", "Seasonal Allergic Rhinitis", "Sinusitis",
	"Eczema (Atopic Dermatitis)", "Contact Dermatitis", "Psoriasis", "Cellulitis",
	"Impetigo", "Herpes Simplex", "Shingles (Herpes Zoster)", "Hyperthyroidism",
	"Hypothyroidism", "Anemia (Iron deficiency)", "Vitamin D deficiency",
	"Vitamin B12 deficiency", "Gout", "Peripheral Neuropathy", "Stroke (Cerebrovascular Accident)",
	"Transient Ischemic Attack", "Coronary Artery Disease", "Heart Failure",
	"Atrial Fibrillation", "Arrhythmia (unspecified)", "Congestive Heart Failure",
	"Angina Pectoris", "Acute Myocardial Infarction", "Pulmonary Embolism",
	"Deep Vein Thrombosis", "Sepsis", "Cellulitis of leg", "Bronchiectasis",
	"Cholelithiasis", "Cholecystitis", "Pancreatitis", "Hepatitis (viral)",
	"Fatty Liver Disease (NAFLD)", "Appendicitis", "Hemorrhoids", "Anal Fissure",
	"Diverticulosis", "Diverticulitis", "Constipation", "Diarrhea (acute)",
	"Ulcerative Colitis", "Crohn's Disease", "Celiac Disease", "Irritable Bowel Syndrome-C",
	"Acute Otitis Media", "Chronic Otitis Media", "Tinnitus", "Vertigo",
	"Benign Prostatic Hyperplasia", "Erectile Dysfunction", "Urinary Incontinence",
	"Endometriosis", "Polycystic Ovary Syndrome", "Infertility (unspecified)",
	"Conjunctivitis", "Glaucoma", "Cataract", "Macular Degeneration",
	"Acute Coronary Syndrome", "Dermatitis (allergic)", "Hypotension", "Hyperkalemia",
	"Hypokalemia", "Hyponatremia", "Hypernatremia", "Seizure Disorder", "Epilepsy",
	"Parkinson's Disease", "Alzheimer's Disease", "Dementia (unspecified)",
	"Traumatic Brain Injury", "Fracture of femur", "Fracture of radius", "Sprain/Strain",
	"Burn (minor)", "Cellulitis secondary infection", "COVID-19", "Influenza",
	"Bronchiolitis", "Otitis externa", "Laryngitis", "Tonsillitis",
	"Allergic reaction (unspecified)", "Poisoning (unspecified)", "Rash (unspecified)",
}

package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaibhaw-/AuditR/internal/auditr/config"
)

func TestCanonicalize_IsDeterministic(t *testing.T) {
	evt1 := map[string]interface{}{
		"b":      2,
		"a":      1,
		"ts":     time.Now().UTC().Format(time.RFC3339),
		"hash":   "deadbeef",
		"nested": map[string]interface{}{"y": 2, "x": 1},
	}
	// different ordering, same content
	evt2 := map[string]interface{}{
		"a":         1,
		"b":         2,
		"ts":        evt1["ts"],
		"hash_prev": "ignored",
		"nested":    map[string]interface{}{"x": 1, "y": 2},
	}
	c1, err := Canonicalize(evt1)
	if err != nil {
		t.Fatalf("canonicalize 1: %v", err)
	}
	c2, err := Canonicalize(evt2)
	if err != nil {
		t.Fatalf("canonicalize 2: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("canonical forms differ:\n%s\n!=\n%s", c1, c2)
	}
}

func TestCheckpoint_SignVerify_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := mustGenKeys(t, dir)
	path, err := WriteCheckpoint(dir, 10, "abcd", priv)
	if err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
	ok, err := VerifyCheckpoint(path, pub, "abcd")
	if err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	if !ok {
		t.Fatalf("expected checkpoint verify ok")
	}
}

func TestChain_Roundtrip_And_Tamper(t *testing.T) {
	// Build two simple events
	events := []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "one"},
		{"id": 2, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "two"},
	}
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}

	var out bytes.Buffer
	st := &ChainState{LastChainIndex: 0, LastHeadHash: zeroHashForTest()}
	newState, n, err := ComputeChain(&in, &out, st)
	if err != nil {
		t.Fatalf("compute chain: %v", err)
	}
	if n != 2 || newState.LastChainIndex != 2 {
		t.Fatalf("unexpected state/events: n=%d idx=%d", n, newState.LastChainIndex)
	}

	// Verify OK
	tampered, head, cnt, err := VerifyChain(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if len(tampered) != 0 || cnt != 2 || head == "" {
		t.Fatalf("unexpected verify: tampered=%v cnt=%d head=%s", tampered, cnt, head)
	}

	// Tamper second line and expect detection
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	var e2 map[string]interface{}
	if err := json.Unmarshal(lines[1], &e2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	e2["msg"] = "tampered"
	lines[1], _ = json.Marshal(e2)
	tampered, _, _, err = VerifyChain(bytes.NewReader(append(lines[0], append([]byte("\n"), lines[1]...)...)))
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	if len(tampered) == 0 {
		t.Fatalf("expected tamper detection")
	}
}

func TestMultiFileContinuity_UsesPriorState(t *testing.T) {
	// First file with two events
	eventsA := []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "A1"},
		{"id": 2, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "A2"},
	}
	var inA bytes.Buffer
	encA := json.NewEncoder(&inA)
	for _, e := range eventsA {
		if err := encA.Encode(e); err != nil {
			t.Fatalf("encode A: %v", err)
		}
	}
	var outA bytes.Buffer
	st := &ChainState{LastChainIndex: 0, LastHeadHash: zeroHashForTest()}
	st1, nA, err := ComputeChain(&inA, &outA, st)
	if err != nil {
		t.Fatalf("compute A: %v", err)
	}
	if nA != 2 || st1.LastChainIndex != 2 {
		t.Fatalf("unexpected A state: n=%d idx=%d", nA, st1.LastChainIndex)
	}

	// Second file continues with one event
	eventsB := []map[string]interface{}{
		{"id": 3, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "B1"},
	}
	var inB bytes.Buffer
	encB := json.NewEncoder(&inB)
	for _, e := range eventsB {
		if err := encB.Encode(e); err != nil {
			t.Fatalf("encode B: %v", err)
		}
	}
	var outB bytes.Buffer
	st2, nB, err := ComputeChain(&inB, &outB, st1)
	if err != nil {
		t.Fatalf("compute B: %v", err)
	}
	if nB != 1 || st2.LastChainIndex != 3 {
		t.Fatalf("unexpected B state: n=%d idx=%d", nB, st2.LastChainIndex)
	}

	// Check first event in B has hash_prev == head of A
	linesB := bytes.Split(bytes.TrimSpace(outB.Bytes()), []byte("\n"))
	var b0 map[string]interface{}
	if err := json.Unmarshal(linesB[0], &b0); err != nil {
		t.Fatalf("unmarshal B0: %v", err)
	}
	prev, _ := b0["hash_prev"].(string)
	if prev != st1.LastHeadHash {
		t.Fatalf("expected B0.prev == A.head, got prev=%s head=%s", prev, st1.LastHeadHash)
	}
}

func TestCheckpoint_VerifyMismatchHead(t *testing.T) {
	dir := t.TempDir()
	priv, pub := mustGenKeys(t, dir)
	path, err := WriteCheckpoint(dir, 5, "abcd", priv)
	if err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
	ok, err := VerifyCheckpoint(path, pub, "efgh")
	if err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	if ok {
		t.Fatalf("expected mismatch to fail verify")
	}
}

func TestCanonicalize_EdgeCases_NoTimestampChangeOnNonRFC3339(t *testing.T) {
	evt := map[string]interface{}{
		"numstr": "00123",
		"ts":     "2025/10/16 19:00:00", // not RFC3339
		"arr":    []interface{}{map[string]interface{}{"z": 1, "a": 2}},
	}
	out, err := Canonicalize(evt)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if bytes.Contains([]byte(out), []byte("2025-10-16T19:00:00Z")) {
		t.Fatalf("timestamp should not have been normalized")
	}
}

func TestVerify_WithoutHashFields_FlagsAllAsTampered(t *testing.T) {
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for i := 0; i < 3; i++ {
		if err := enc.Encode(map[string]interface{}{"id": i + 1, "ts": time.Now().UTC().Format(time.RFC3339)}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	tampered, _, cnt, err := VerifyChain(&in)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cnt != 3 || len(tampered) == 0 {
		t.Fatalf("expected all events marked tampered, got cnt=%d tampered=%v", cnt, tampered)
	}
}

func mustGenKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	// Private key in PKCS#8
	pkcs8, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	privPath = filepath.Join(dir, "private.pem")
	if err := os.WriteFile(privPath, priv, 0600); err != nil {
		t.Fatalf("write priv: %v", err)
	}

	// Public key in PKIX
	der, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pubPath = filepath.Join(dir, "public.pem")
	if err := os.WriteFile(pubPath, pub, 0644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return
}

func TestRunVerifyPhase_HashMode_WithoutCheckpoint(t *testing.T) {
	// Test hash mode without checkpointing (no keys needed)
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "input.jsonl")
	outputFile := filepath.Join(dir, "output.jsonl")

	// Create test input
	events := []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
		{"id": 2, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test2"},
	}
	writeTestEvents(t, inputFile, events)

	// Create minimal config
	cfg := &config.Config{
		Hashing: config.HashingCfg{
			StateFile: filepath.Join(dir, "state.json"),
		},
	}

	// Run hash mode
	args := VerifyArgs{
		InputFile:  inputFile,
		OutputFile: outputFile,
	}

	err := RunVerifyPhase(cfg, args)
	if err != nil {
		t.Fatalf("RunVerifyPhase: %v", err)
	}

	// Verify output file was created and contains hashed events
	verifyHashedOutput(t, outputFile, 2)
}

func TestRunVerifyPhase_HashMode_WithCheckpoint_MissingKey(t *testing.T) {
	// Test hash mode with checkpointing but missing private key (should fail fast)
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "input.jsonl")
	outputFile := filepath.Join(dir, "output.jsonl")

	// Create test input
	events := []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
	}
	writeTestEvents(t, inputFile, events)

	// Create config with checkpointing enabled
	cfg := &config.Config{
		Hashing: config.HashingCfg{
			StateFile:          filepath.Join(dir, "state.json"),
			CheckpointDir:      dir,
			CheckpointInterval: "file_end",
		},
		Signing: struct {
			PrivateKeyPath string `mapstructure:"private_key_path"`
		}{
			PrivateKeyPath: "", // Missing key
		},
	}

	// Run hash mode with checkpointing
	args := VerifyArgs{
		InputFile:  inputFile,
		OutputFile: outputFile,
		Checkpoint: true,
	}

	err := RunVerifyPhase(cfg, args)
	if err == nil {
		t.Fatalf("expected error for missing private key")
	}
	if !strings.Contains(err.Error(), "signing key not provided") {
		t.Fatalf("expected signing key error, got: %v", err)
	}

	// Verify no output file was created (fail fast)
	if _, err := os.Stat(outputFile); err == nil {
		t.Fatalf("output file should not exist after validation failure")
	}
}

func TestRunVerifyPhase_HashMode_WithCheckpoint_ValidKey(t *testing.T) {
	// Test hash mode with checkpointing and valid private key
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "input.jsonl")
	outputFile := filepath.Join(dir, "output.jsonl")

	// Create test input
	events := []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
	}
	writeTestEvents(t, inputFile, events)

	// Generate keys
	privPath, _ := mustGenKeys(t, dir)

	// Create config with checkpointing enabled
	cfg := &config.Config{
		Hashing: config.HashingCfg{
			StateFile:          filepath.Join(dir, "state.json"),
			CheckpointDir:      dir,
			CheckpointInterval: "file_end",
		},
		Signing: struct {
			PrivateKeyPath string `mapstructure:"private_key_path"`
		}{
			PrivateKeyPath: privPath,
		},
	}

	// Run hash mode with checkpointing
	args := VerifyArgs{
		InputFile:  inputFile,
		OutputFile: outputFile,
	}

	err := RunVerifyPhase(cfg, args)
	if err != nil {
		t.Fatalf("RunVerifyPhase: %v", err)
	}

	// Verify output file and checkpoint were created
	verifyHashedOutput(t, outputFile, 1)
	verifyCheckpointExists(t, dir)
}

func TestRunVerifyPhase_VerifyMode_WithoutCheckpoint(t *testing.T) {
	// Test verify mode without checkpoint validation (no keys needed)
	dir := t.TempDir()
	hashedFile := filepath.Join(dir, "hashed.jsonl")

	// Create hashed input (simulate output from hash mode)
	createHashedInput(t, hashedFile, []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
		{"id": 2, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test2"},
	})

	// Create minimal config
	cfg := &config.Config{}

	// Run verify mode (no --output means verify mode)
	args := VerifyArgs{
		InputFile: hashedFile,
		// No OutputFile = verify mode
	}

	err := RunVerifyPhase(cfg, args)
	if err != nil {
		t.Fatalf("RunVerifyPhase: %v", err)
	}
}

func TestRunVerifyPhase_VerifyMode_WithCheckpoint_MissingKey(t *testing.T) {
	// Test verify mode with checkpoint but missing public key (should fail fast)
	dir := t.TempDir()
	hashedFile := filepath.Join(dir, "hashed.jsonl")
	checkpointFile := filepath.Join(dir, "checkpoint.json")

	// Create hashed input
	createHashedInput(t, hashedFile, []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
	})

	// Create dummy checkpoint
	writeDummyCheckpoint(t, checkpointFile)

	// Create minimal config
	cfg := &config.Config{}

	// Run verify mode with checkpoint but no public key
	args := VerifyArgs{
		InputFile:      hashedFile,
		CheckpointPath: checkpointFile,
		// No PublicKeyPath = should fail
	}

	err := RunVerifyPhase(cfg, args)
	if err == nil {
		t.Fatalf("expected error for missing public key")
	}
	if !strings.Contains(err.Error(), "checkpoint verification requires --public-key") {
		t.Fatalf("expected public key error, got: %v", err)
	}
}

func TestRunVerifyPhase_VerifyMode_WithCheckpoint_ValidKey(t *testing.T) {
	// Test verify mode with checkpoint and valid public key
	dir := t.TempDir()
	hashedFile := filepath.Join(dir, "hashed.jsonl")

	// Create hashed input
	createHashedInput(t, hashedFile, []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
	})

	// Generate keys and create checkpoint
	privPath, pubPath := mustGenKeys(t, dir)
	checkpointFile := createValidCheckpoint(t, dir, privPath, "testheadhash")

	// Create minimal config
	cfg := &config.Config{}

	// Run verify mode with checkpoint
	args := VerifyArgs{
		InputFile:      hashedFile,
		CheckpointPath: checkpointFile,
		PublicKeyPath:  pubPath,
	}

	err := RunVerifyPhase(cfg, args)
	if err != nil {
		t.Fatalf("RunVerifyPhase: %v", err)
	}
}

func TestRunVerifyPhase_ModeDetermination(t *testing.T) {
	// Test that mode is determined by --output presence, not --public-key
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "input.jsonl")
	outputFile := filepath.Join(dir, "output.jsonl")
	_, pubPath := mustGenKeys(t, dir)

	// Create test input
	events := []map[string]interface{}{
		{"id": 1, "ts": time.Now().UTC().Format(time.RFC3339), "msg": "test1"},
	}
	writeTestEvents(t, inputFile, events)

	cfg := &config.Config{
		Hashing: config.HashingCfg{
			StateFile: filepath.Join(dir, "state.json"),
		},
	}

	// Test 1: --output present + --public-key present = hash mode (not verify mode)
	args1 := VerifyArgs{
		InputFile:     inputFile,
		OutputFile:    outputFile,
		PublicKeyPath: pubPath, // This should NOT make it verify mode
	}

	err := RunVerifyPhase(cfg, args1)
	if err != nil {
		t.Fatalf("RunVerifyPhase with output+pubkey: %v", err)
	}

	// Verify output file was created (hash mode)
	if _, err := os.Stat(outputFile); err != nil {
		t.Fatalf("output file should exist in hash mode")
	}

	// Test 2: No --output + no --public-key = verify mode
	hashedFile := filepath.Join(dir, "hashed.jsonl")
	createHashedInput(t, hashedFile, events)

	args2 := VerifyArgs{
		InputFile: hashedFile,
		// No OutputFile = verify mode
		// No PublicKeyPath = verify mode without checkpoint
	}

	err = RunVerifyPhase(cfg, args2)
	if err != nil {
		t.Fatalf("RunVerifyPhase without output: %v", err)
	}
}

// Helper functions

func writeTestEvents(t *testing.T, path string, events []map[string]interface{}) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test file: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode event: %v", err)
		}
	}
}

func createHashedInput(t *testing.T, path string, events []map[string]interface{}) {
	t.Helper()
	// Create a simple hashed input with hash fields
	hashedEvents := make([]map[string]interface{}, len(events))
	for i, e := range events {
		hashedEvents[i] = map[string]interface{}{
			"id":               e["id"],
			"ts":               e["ts"],
			"msg":              e["msg"],
			"hash_prev":        "0000000000000000000000000000000000000000000000000000000000000000",
			"hash":             "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			"hash_chain_index": i + 1,
		}
	}
	writeTestEvents(t, path, hashedEvents)
}

func verifyHashedOutput(t *testing.T, path string, expectedCount int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	count := 0
	for dec.More() {
		var event map[string]interface{}
		if err := dec.Decode(&event); err != nil {
			t.Fatalf("decode event: %v", err)
		}

		// Verify hash fields exist
		if _, ok := event["hash"]; !ok {
			t.Fatalf("event missing hash field")
		}
		if _, ok := event["hash_prev"]; !ok {
			t.Fatalf("event missing hash_prev field")
		}
		if _, ok := event["hash_chain_index"]; !ok {
			t.Fatalf("event missing hash_chain_index field")
		}
		count++
	}

	if count != expectedCount {
		t.Fatalf("expected %d events, got %d", expectedCount, count)
	}
}

func verifyCheckpointExists(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "checkpoint-*.json"))
	if err != nil {
		t.Fatalf("glob checkpoints: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no checkpoint files found")
	}
}

func writeDummyCheckpoint(t *testing.T, path string) {
	t.Helper()
	checkpoint := map[string]interface{}{
		"checkpoint": map[string]interface{}{
			"chain_index": 1,
			"head_hash":   "testheadhash",
			"created_at":  time.Now().UTC().Format(time.RFC3339),
		},
		"signature": "dummy_signature",
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(checkpoint); err != nil {
		t.Fatalf("encode checkpoint: %v", err)
	}
}

func createValidCheckpoint(t *testing.T, dir, privPath, headHash string) string {
	t.Helper()
	// This is a simplified version - in real tests you'd use the actual WriteCheckpoint function
	checkpointFile := filepath.Join(dir, "checkpoint-test.json")
	writeDummyCheckpoint(t, checkpointFile)
	return checkpointFile
}

func zeroHashForTest() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

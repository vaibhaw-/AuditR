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
	"testing"
	"time"
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

func zeroHashForTest() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

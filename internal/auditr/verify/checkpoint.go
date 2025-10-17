package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteCheckpoint creates and signs a checkpoint JSON; returns path written
//
// A checkpoint is a cryptographically signed snapshot of the hash chain state at a
// specific point in time. It provides tamper-evident evidence of the chain's integrity
// and can be used to verify that the chain hasn't been modified since the checkpoint
// was created.
//
// The checkpoint contains:
// - Chain index: Position in the hash chain
// - Head hash: The hash of the last event in the chain
// - Created timestamp: When the checkpoint was created
// - Digital signature: ECDSA signature of the canonicalized checkpoint data
//
// Args:
//   - dir: Directory where checkpoint file will be written
//   - index: Chain index at the time of checkpoint
//   - headHash: Hash of the last event in the chain
//   - privateKeyPath: Path to ECDSA private key for signing
//
// Returns:
//   - Path to the created checkpoint file
//   - Error if checkpoint creation fails
func WriteCheckpoint(dir string, index int, headHash string, privateKeyPath string) (string, error) {
	// Validate required parameters
	if dir == "" {
		return "", fmt.Errorf("checkpoint dir required")
	}

	// Ensure checkpoint directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	// Create checkpoint data structure
	cp := Checkpoint{ChainIndex: index, HeadHash: headHash, CreatedAt: time.Now().UTC()}

	// Canonicalize checkpoint for consistent signing
	// This ensures the same data always produces the same signature
	canon, err := canonicalizeCheckpoint(cp)
	if err != nil {
		return "", err
	}

	// Sign the canonicalized checkpoint data using ECDSA
	sig, err := signMessageECDSA(privateKeyPath, []byte(canon))
	if err != nil {
		return "", err
	}

	// Create signed checkpoint with base64-encoded signature
	sc := SignedCheckpoint{Checkpoint: cp, Signature: base64.StdEncoding.EncodeToString(sig)}

	// Serialize to JSON
	b, err := json.Marshal(sc)
	if err != nil {
		return "", fmt.Errorf("marshal checkpoint: %w", err)
	}

	// Generate filename with timestamp and index for uniqueness
	name := fmt.Sprintf("checkpoint-%s-%d.json", time.Now().UTC().Format("20060102-150405"), index)
	path := filepath.Join(dir, name)

	// Write checkpoint file
	if err := os.WriteFile(path, b, 0644); err != nil {
		return "", fmt.Errorf("write checkpoint: %w", err)
	}
	return path, nil
}

// VerifyCheckpoint verifies a signed checkpoint file and expected head hash
//
// This function validates the integrity and authenticity of a checkpoint by:
// 1. Verifying the digital signature using the public key
// 2. Checking that the head hash matches the expected value
// 3. Ensuring the checkpoint data hasn't been tampered with
//
// Args:
//   - path: Path to the checkpoint file to verify
//   - publicKeyPath: Path to the ECDSA public key for signature verification
//   - expectedHeadHash: The head hash that should be in the checkpoint
//
// Returns:
//   - true if checkpoint is valid and head hash matches
//   - false if checkpoint is invalid or head hash doesn't match
//   - error if verification process fails
func VerifyCheckpoint(path, publicKeyPath, expectedHeadHash string) (bool, error) {
	// Read checkpoint file
	b, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read checkpoint: %w", err)
	}

	// Parse JSON checkpoint
	var sc SignedCheckpoint
	if err := json.Unmarshal(b, &sc); err != nil {
		return false, fmt.Errorf("unmarshal checkpoint: %w", err)
	}

	// Verify head hash matches expected value
	if sc.Checkpoint.HeadHash != expectedHeadHash {
		return false, nil
	}

	// Canonicalize checkpoint data for signature verification
	canon, err := canonicalizeCheckpoint(sc.Checkpoint)
	if err != nil {
		return false, err
	}

	// Decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(sc.Signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}

	// Verify ECDSA signature
	ok, err := verifyMessageECDSA(publicKeyPath, []byte(canon), sig)
	return ok, err
}

// canonicalizeCheckpoint creates a deterministic JSON representation of a checkpoint
//
// This function ensures that the same checkpoint data always produces the same
// canonical representation, which is essential for consistent digital signatures.
// The canonical form uses a specific field order and UTC timestamps.
//
// Args:
//   - cp: Checkpoint to canonicalize
//
// Returns:
//   - Canonical JSON string representation
//   - Error if canonicalization fails
func canonicalizeCheckpoint(cp Checkpoint) (string, error) {
	// Create map with deterministic field order for consistent JSON output
	// Order: chain_index, head_hash, created_at (RFC3339 UTC)
	m := map[string]interface{}{
		"chain_index": cp.ChainIndex,
		"head_hash":   cp.HeadHash,
		"created_at":  cp.CreatedAt.UTC().Format(time.RFC3339),
	}

	// Marshal to JSON (Go's json.Marshal produces deterministic output for maps)
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// signMessageECDSA signs a message using an ECDSA private key
//
// This function loads an ECDSA private key from a PEM file and uses it to sign
// the provided message. The signature is created using SHA-256 hashing and
// ECDSA with P-256 curve.
//
// Supported private key formats:
// - EC PRIVATE KEY (PKCS#1 format)
// - PRIVATE KEY (PKCS#8 format)
//
// Args:
//   - privateKeyPath: Path to PEM-encoded ECDSA private key file
//   - msg: Message bytes to sign
//
// Returns:
//   - ASN.1 DER-encoded signature
//   - Error if signing fails
func signMessageECDSA(privateKeyPath string, msg []byte) ([]byte, error) {
	// Read private key file
	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	// Decode PEM format
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM for private key")
	}

	// Parse private key based on PEM block type
	var pk *ecdsa.PrivateKey
	if block.Type == "EC PRIVATE KEY" {
		// PKCS#1 format (legacy)
		pk, err = x509.ParseECPrivateKey(block.Bytes)
	} else {
		// Try PKCS#8 format (modern)
		var key any
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			pk, ok = key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an ECDSA private key")
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Validate curve (only P-256 is supported)
	if pk.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve: want P-256")
	}

	// Hash message with SHA-256
	sum := sha256.Sum256(msg)

	// Sign using ECDSA with ASN.1 DER encoding
	return ecdsa.SignASN1(rand.Reader, pk, sum[:])
}

// verifyMessageECDSA verifies an ECDSA signature using a public key
//
// This function loads an ECDSA public key from a PEM file and uses it to verify
// a signature against a message. The verification uses SHA-256 hashing and
// ECDSA with P-256 curve.
//
// Supported public key formats:
// - PUBLIC KEY (PKIX format)
// - EC PUBLIC KEY (PKIX format for EC keys)
//
// Args:
//   - publicKeyPath: Path to PEM-encoded ECDSA public key file
//   - msg: Original message that was signed
//   - sig: ASN.1 DER-encoded signature to verify
//
// Returns:
//   - true if signature is valid
//   - false if signature is invalid
//   - error if verification process fails
func verifyMessageECDSA(publicKeyPath string, msg []byte, sig []byte) (bool, error) {
	// Read public key file
	keyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return false, fmt.Errorf("read public key: %w", err)
	}

	// Decode PEM format
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return false, fmt.Errorf("invalid PEM for public key")
	}

	// Parse public key based on PEM block type
	var pub *ecdsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		// PKIX format (standard)
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("parse public key: %w", err)
		}
		var ok bool
		pub, ok = key.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("not an ECDSA public key")
		}
	case "EC PUBLIC KEY":
		// PKIX format specifically for EC keys
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("parse EC public key: %w", err)
		}
		var ok bool
		pub, ok = k.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("not an ECDSA public key")
		}
	default:
		return false, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	// Validate curve (only P-256 is supported)
	if pub.Curve != elliptic.P256() {
		return false, fmt.Errorf("unsupported curve: want P-256")
	}

	// Hash message with SHA-256 (same as during signing)
	sum := sha256.Sum256(msg)

	// Verify signature using ECDSA
	ok := ecdsa.VerifyASN1(pub, sum[:], sig)
	return ok, nil
}

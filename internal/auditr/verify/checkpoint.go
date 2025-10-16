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
func WriteCheckpoint(dir string, index int, headHash string, privateKeyPath string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("checkpoint dir required")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	cp := Checkpoint{ChainIndex: index, HeadHash: headHash, CreatedAt: time.Now().UTC()}
	canon, err := canonicalizeCheckpoint(cp)
	if err != nil {
		return "", err
	}

	sig, err := signMessageECDSA(privateKeyPath, []byte(canon))
	if err != nil {
		return "", err
	}

	sc := SignedCheckpoint{Checkpoint: cp, Signature: base64.StdEncoding.EncodeToString(sig)}
	b, err := json.Marshal(sc)
	if err != nil {
		return "", fmt.Errorf("marshal checkpoint: %w", err)
	}

	name := fmt.Sprintf("checkpoint-%s-%d.json", time.Now().UTC().Format("20060102-150405"), index)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0644); err != nil {
		return "", fmt.Errorf("write checkpoint: %w", err)
	}
	return path, nil
}

// VerifyCheckpoint verifies a signed checkpoint file and expected head hash
func VerifyCheckpoint(path, publicKeyPath, expectedHeadHash string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read checkpoint: %w", err)
	}
	var sc SignedCheckpoint
	if err := json.Unmarshal(b, &sc); err != nil {
		return false, fmt.Errorf("unmarshal checkpoint: %w", err)
	}
	if sc.Checkpoint.HeadHash != expectedHeadHash {
		return false, nil
	}
	canon, err := canonicalizeCheckpoint(sc.Checkpoint)
	if err != nil {
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(sc.Signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	ok, err := verifyMessageECDSA(publicKeyPath, []byte(canon), sig)
	return ok, err
}

func canonicalizeCheckpoint(cp Checkpoint) (string, error) {
	// Deterministic order: chain_index, head_hash, created_at (RFC3339 UTC)
	m := map[string]interface{}{
		"chain_index": cp.ChainIndex,
		"head_hash":   cp.HeadHash,
		"created_at":  cp.CreatedAt.UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func signMessageECDSA(privateKeyPath string, msg []byte) ([]byte, error) {
	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM for private key")
	}
	var pk *ecdsa.PrivateKey
	if block.Type == "EC PRIVATE KEY" {
		pk, err = x509.ParseECPrivateKey(block.Bytes)
	} else {
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
	if pk.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve: want P-256")
	}
	sum := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, pk, sum[:])
}

func verifyMessageECDSA(publicKeyPath string, msg []byte, sig []byte) (bool, error) {
	keyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return false, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return false, fmt.Errorf("invalid PEM for public key")
	}
	var pub *ecdsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
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
	if pub.Curve != elliptic.P256() {
		return false, fmt.Errorf("unsupported curve: want P-256")
	}
	sum := sha256.Sum256(msg)
	ok := ecdsa.VerifyASN1(pub, sum[:], sig)
	return ok, nil
}

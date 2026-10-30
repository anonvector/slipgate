package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// GenerateSoarKeys generates an Ed25519 keypair and writes them to files in
// the format soar-server uses (base64 seed / base64 public key).
// Returns the base64-encoded public key.
func GenerateSoarKeys(privKeyPath, pubKeyPath string) (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}
	return writeSoarKeys(seed, privKeyPath, pubKeyPath)
}

// ImportSoarKey validates a base64-encoded Ed25519 seed, derives its public
// key, and writes both to files. Returns the base64-encoded public key.
func ImportSoarKey(privKeyB64, privKeyPath, pubKeyPath string) (string, error) {
	seed, err := parseSoarSeed(privKeyB64)
	if err != nil {
		return "", err
	}
	return writeSoarKeys(seed, privKeyPath, pubKeyPath)
}

// LoadSoarKey reads a base64 Ed25519 seed file and returns the private key.
func LoadSoarKey(path string) (ed25519.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := parseSoarSeed(string(contents))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// parseSoarSeed decodes a base64 Ed25519 seed, ignoring surrounding whitespace.
func parseSoarSeed(b64 string) ([]byte, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("invalid private key base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return seed, nil
}

func writeSoarKeys(seed []byte, privKeyPath, pubKeyPath string) (string, error) {
	priv := ed25519.NewKeyFromSeed(seed)

	if err := os.WriteFile(privKeyPath, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := os.WriteFile(pubKeyPath, []byte(pubB64+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return pubB64, nil
}

package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func LoadOrGenerateSecret(secretPath string) ([]byte, error) {
	_, err := os.Stat(secretPath)
	if os.IsNotExist(err) {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate secret: %w", err)
		}
		if err := os.WriteFile(secretPath, secret, 0600); err != nil {
			return nil, fmt.Errorf("failed to save secret: %w", err)
		}
		return secret, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat secret file: %w", err)
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}
	return secret, nil
}

func LoadOrGeneratePrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	_, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		if err := SavePrivateKey(keyPath, key); err != nil {
			return nil, fmt.Errorf("failed to save private key: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat private key file: %w", err)
	}
	return LoadPrivateKey(keyPath)
}

func SavePrivateKey(keyPath string, privateKey *rsa.PrivateKey) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(keyPath, keyPEM, 0600)
}

func LoadPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey.(*rsa.PrivateKey), nil
}

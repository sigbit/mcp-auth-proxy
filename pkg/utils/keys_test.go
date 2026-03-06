package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretFromBase64_Valid(t *testing.T) {
	secret := make([]byte, SecretSize)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(secret)
	decoded, err := SecretFromBase64(encoded)
	require.NoError(t, err)
	require.Equal(t, secret, decoded)
}

func TestSecretFromBase64_InvalidBase64(t *testing.T) {
	_, err := SecretFromBase64("not-valid-base64!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode base64")
}

func TestSecretFromBase64_WrongLength(t *testing.T) {
	short := make([]byte, 16)
	_, err := rand.Read(short)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(short)
	_, err = SecretFromBase64(encoded)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be exactly 32 bytes")
}

func TestPrivateKeyFromPEM_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}))

	parsed, err := PrivateKeyFromPEM(pemStr)
	require.NoError(t, err)
	require.True(t, key.Equal(parsed))
}

func TestPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := PrivateKeyFromPEM("not a pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestPrivateKeyFromPEM_NonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}))

	_, err = PrivateKeyFromPEM(pemStr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not RSA")
}

package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func mustPrivateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func mustPublicKeyPEM(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func mustPKCS8PrivateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func Test_PrivateKeyFromCredentials(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key := mustECDSAKey(t)
	pemData := mustPrivateKeyPEM(t, key)

	t.Run("inline PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: pemData,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Equal(result))
	})

	t.Run("file PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		path := filepath.Join(t.TempDir(), "key.pem")
		r.NoError(os.WriteFile(path, []byte(pemData), 0o600))
		result, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEMFile: path,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Equal(result))
	})

	t.Run("PKCS8 format", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		pkcs8PEM := mustPKCS8PrivateKeyPEM(t, key)
		result, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: pkcs8PEM,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Equal(result))
	})

	t.Run("empty credentials returns nil", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := PrivateKeyFromCredentials(map[string]string{})
		r.NoError(err)
		r.Nil(result)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		t.Parallel()
		_, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: "not-a-pem",
		})
		r.Error(err)
	})

	t.Run("non-existent file", func(t *testing.T) {
		t.Parallel()
		_, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEMFile: "/nonexistent/path/key.pem",
		})
		r.Error(err)
	})
}

func Test_PublicKeyFromCredentials(t *testing.T) {
	t.Parallel()

	key := mustECDSAKey(t)
	pubPEM := mustPublicKeyPEM(t, &key.PublicKey)

	t.Run("inline PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPublicKeyPEM: pubPEM,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.PublicKey.Equal(result))
	})

	t.Run("derive from private key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		privPEM := mustPrivateKeyPEM(t, key)
		result, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: privPEM,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.PublicKey.Equal(result))
	})

	t.Run("matching public and private key succeeds", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		privPEM := mustPrivateKeyPEM(t, key)
		result, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPublicKeyPEM:  pubPEM,
			CredentialKeyPrivateKeyPEM: privPEM,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.PublicKey.Equal(result))
	})

	t.Run("mismatched public and private key returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		otherKey := mustECDSAKey(t)
		otherPrivPEM := mustPrivateKeyPEM(t, otherKey)
		_, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPublicKeyPEM:  pubPEM,
			CredentialKeyPrivateKeyPEM: otherPrivPEM,
		})
		r.Error(err)
		r.Contains(err.Error(), "provided public key does not match the private key")
	})

	t.Run("empty credentials returns nil", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := PublicKeyFromCredentials(map[string]string{})
		r.NoError(err)
		r.Nil(result)
	})
}

func Test_OIDCTokenFromCredentials(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	r.Equal("my-token", OIDCTokenFromCredentials(map[string]string{
		CredentialKeyOIDCToken: "my-token",
	}))
	r.Equal("", OIDCTokenFromCredentials(map[string]string{}))
}

func Test_TrustedRootFromCredentials(t *testing.T) {
	t.Parallel()

	t.Run("inline JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := TrustedRootFromCredentials(map[string]string{
			CredentialKeyTrustedRootJSON: `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`,
		})
		r.NoError(err)
		r.Contains(string(result), "trustedroot")
	})

	t.Run("file path", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		path := filepath.Join(t.TempDir(), "trusted_root.json")
		r.NoError(os.WriteFile(path, []byte(`{"test":"data"}`), 0o600))
		result, err := TrustedRootFromCredentials(map[string]string{
			CredentialKeyTrustedRootJSONFile: path,
		})
		r.NoError(err)
		r.Equal(`{"test":"data"}`, string(result))
	})

	t.Run("empty returns nil", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := TrustedRootFromCredentials(map[string]string{})
		r.NoError(err)
		r.Nil(result)
	})
}

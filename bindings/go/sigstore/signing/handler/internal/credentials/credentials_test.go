package credentials

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// key generation helpers

func mustECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

func mustEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

func mustECPrivateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func mustPKCS8PrivateKeyPEM(t *testing.T, key interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func mustPublicKeyPEM(t *testing.T, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func Test_PrivateKeyFromCredentials(t *testing.T) {
	t.Parallel()

	t.Run("empty credentials returns nil", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := PrivateKeyFromCredentials(map[string]string{})
		r.NoError(err)
		r.Nil(result)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		_, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: "not-a-pem",
		})
		r.Error(err)
	})

	t.Run("non-existent file", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		_, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEMFile: "/nonexistent/path/key.pem",
		})
		r.Error(err)
	})

	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	} {
		t.Run("ECDSA "+tc.name, func(t *testing.T) {
			t.Parallel()
			key := mustECDSAKey(t, tc.curve)

			t.Run("SEC1 inline PEM", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				result, err := PrivateKeyFromCredentials(map[string]string{
					CredentialKeyPrivateKeyPEM: mustECPrivateKeyPEM(t, key),
				})
				r.NoError(err)
				r.NotNil(result)
				r.True(key.Equal(result))
			})

			t.Run("SEC1 file PEM", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				path := filepath.Join(t.TempDir(), "key.pem")
				r.NoError(os.WriteFile(path, []byte(mustECPrivateKeyPEM(t, key)), 0o600))
				result, err := PrivateKeyFromCredentials(map[string]string{
					CredentialKeyPrivateKeyPEMFile: path,
				})
				r.NoError(err)
				r.NotNil(result)
				r.True(key.Equal(result))
			})

			t.Run("PKCS8 inline PEM", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				result, err := PrivateKeyFromCredentials(map[string]string{
					CredentialKeyPrivateKeyPEM: mustPKCS8PrivateKeyPEM(t, key),
				})
				r.NoError(err)
				r.NotNil(result)
				r.True(key.Equal(result))
			})
		})
	}

	t.Run("Ed25519 PKCS8 inline PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		result, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: mustPKCS8PrivateKeyPEM(t, key),
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Equal(result))
	})

	t.Run("Ed25519 PKCS8 file PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		path := filepath.Join(t.TempDir(), "key.pem")
		r.NoError(os.WriteFile(path, []byte(mustPKCS8PrivateKeyPEM(t, key)), 0o600))
		result, err := PrivateKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEMFile: path,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Equal(result))
	})
}

func Test_PublicKeyFromCredentials(t *testing.T) {
	t.Parallel()

	t.Run("empty credentials returns nil", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := PublicKeyFromCredentials(map[string]string{})
		r.NoError(err)
		r.Nil(result)
	})

	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	} {
		t.Run("ECDSA "+tc.name, func(t *testing.T) {
			t.Parallel()
			key := mustECDSAKey(t, tc.curve)
			pubPEM := mustPublicKeyPEM(t, &key.PublicKey)
			privPEM := mustECPrivateKeyPEM(t, key)

			t.Run("inline public key PEM", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				result, err := PublicKeyFromCredentials(map[string]string{
					CredentialKeyPublicKeyPEM: pubPEM,
				})
				r.NoError(err)
				r.NotNil(result)
				r.True(key.PublicKey.Equal(result))
			})

			t.Run("derived from private key", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				result, err := PublicKeyFromCredentials(map[string]string{
					CredentialKeyPrivateKeyPEM: privPEM,
				})
				r.NoError(err)
				r.NotNil(result)
				r.True(key.PublicKey.Equal(result))
			})

			t.Run("matching public and private key", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				result, err := PublicKeyFromCredentials(map[string]string{
					CredentialKeyPublicKeyPEM:  pubPEM,
					CredentialKeyPrivateKeyPEM: privPEM,
				})
				r.NoError(err)
				r.NotNil(result)
				r.True(key.PublicKey.Equal(result))
			})

			t.Run("mismatched public and private key", func(t *testing.T) {
				t.Parallel()
				r := require.New(t)
				otherKey := mustECDSAKey(t, tc.curve)
				_, err := PublicKeyFromCredentials(map[string]string{
					CredentialKeyPublicKeyPEM:  pubPEM,
					CredentialKeyPrivateKeyPEM: mustECPrivateKeyPEM(t, otherKey),
				})
				r.Error(err)
				r.Contains(err.Error(), "does not match")
			})
		})
	}

	t.Run("Ed25519 inline public key PEM", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		pubPEM := mustPublicKeyPEM(t, key.Public())
		result, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPublicKeyPEM: pubPEM,
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Public().(ed25519.PublicKey).Equal(result))
	})

	t.Run("Ed25519 derived from private key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		result, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPrivateKeyPEM: mustPKCS8PrivateKeyPEM(t, key),
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Public().(ed25519.PublicKey).Equal(result))
	})

	t.Run("Ed25519 matching public and private key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		pubPEM := mustPublicKeyPEM(t, key.Public())
		result, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPublicKeyPEM:  pubPEM,
			CredentialKeyPrivateKeyPEM: mustPKCS8PrivateKeyPEM(t, key),
		})
		r.NoError(err)
		r.NotNil(result)
		r.True(key.Public().(ed25519.PublicKey).Equal(result))
	})

	t.Run("Ed25519 mismatched public and private key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		otherKey := mustEd25519Key(t)
		pubPEM := mustPublicKeyPEM(t, key.Public())
		_, err := PublicKeyFromCredentials(map[string]string{
			CredentialKeyPublicKeyPEM:  pubPEM,
			CredentialKeyPrivateKeyPEM: mustPKCS8PrivateKeyPEM(t, otherKey),
		})
		r.Error(err)
		r.Contains(err.Error(), "does not match")
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

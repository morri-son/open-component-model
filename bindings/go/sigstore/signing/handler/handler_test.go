package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"

	"github.com/stretchr/testify/require"
)

func newHandler(t *testing.T) *Handler {
	t.Helper()
	return New()
}

func defaultConfig() *v1alpha1.Config {
	cfg := &v1alpha1.Config{}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))
	return cfg
}

func Test_Handler_GetSigningHandlerScheme(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	h := newHandler(t)
	r.Equal(v1alpha1.Scheme, h.GetSigningHandlerScheme())
}

func Test_Handler_GetSigningCredentialConsumerIdentity(t *testing.T) {
	t.Parallel()

	t.Run("returns identity with algorithm and signature name", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		id, err := h.GetSigningCredentialConsumerIdentity(
			t.Context(),
			"my-signature",
			descruntime.Digest{
				HashAlgorithm:          "SHA-256",
				NormalisationAlgorithm: "jsonNormalisation/v2",
				Value:                  "abc123",
			},
			defaultConfig(),
		)
		r.NoError(err)
		r.NotNil(id)
		r.Equal(v1alpha1.AlgorithmSigstore, id[IdentityAttributeAlgorithm])
		r.Equal("my-signature", id[IdentityAttributeSignature])

		idType := id.GetType()
		r.Equal(credentials.IdentityTypeSigstore, idType)
	})
}

func Test_Handler_GetVerifyingCredentialConsumerIdentity(t *testing.T) {
	t.Parallel()

	t.Run("returns identity for sigstore bundle media type", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		sig := descruntime.Signature{
			Name: "my-signature",
			Digest: descruntime.Digest{
				HashAlgorithm:          "SHA-256",
				NormalisationAlgorithm: "jsonNormalisation/v2",
				Value:                  "abc123",
			},
			Signature: descruntime.SignatureInfo{
				Algorithm: v1alpha1.AlgorithmSigstore,
				MediaType: v1alpha1.MediaTypeSigstoreBundle,
				Value:     "some-bundle-data",
			},
		}

		id, err := h.GetVerifyingCredentialConsumerIdentity(t.Context(), sig, defaultConfig())
		r.NoError(err)
		r.NotNil(id)
		r.Equal(v1alpha1.AlgorithmSigstore, id[IdentityAttributeAlgorithm])
		r.Equal("my-signature", id[IdentityAttributeSignature])

		idType := id.GetType()
		r.Equal(credentials.IdentityTypeSigstore, idType)
	})

	t.Run("rejects unsupported media type", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		sig := descruntime.Signature{
			Name: "my-signature",
			Signature: descruntime.SignatureInfo{
				Algorithm: "other",
				MediaType: "application/vnd.unknown",
				Value:     "some-data",
			},
		}

		_, err := h.GetVerifyingCredentialConsumerIdentity(t.Context(), sig, defaultConfig())
		r.Error(err)
		r.Contains(err.Error(), "unsupported media type")
	})
}

func Test_Handler_Sign_InvalidConfig(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	h := newHandler(t)

	// Pass a Raw config with the right type but invalid JSON — scheme.Convert
	// will fail during unmarshal.
	badCfg := &runtime.Raw{
		Data: []byte(`{invalid`),
	}
	badCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	_, err := h.Sign(t.Context(), sampleDigest(t), badCfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "convert config")
}

func Test_Handler_Verify_InvalidConfig(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	h := newHandler(t)

	badCfg := &runtime.Raw{
		Data: []byte(`{invalid`),
	}
	badCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: sampleDigest(t),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     "dW51c2Vk",
		},
	}

	err := h.Verify(t.Context(), signed, badCfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "convert config")
}

// ---- helpers for sign tests ----

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func pemEncodePrivateKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func pemEncodePublicKey(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sampleDigest(t *testing.T) descruntime.Digest {
	t.Helper()
	h := sha256.Sum256([]byte("test content for sigstore signing"))
	return descruntime.Digest{
		HashAlgorithm:          "SHA-256",
		NormalisationAlgorithm: "jsonNormalisation/v2",
		Value:                  hex.EncodeToString(h[:]),
	}
}

func offlineConfig() *v1alpha1.Config {
	cfg := &v1alpha1.Config{
		SkipRekor: true,
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))
	return cfg
}

// ---- Sign tests ----

func Test_Handler_Sign(t *testing.T) {
	t.Parallel()

	t.Run("key-based sign produces valid bundle (offline)", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		creds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), sampleDigest(t), offlineConfig(), creds)
		r.NoError(err)

		r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
		r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
		r.NotEmpty(sigInfo.Value)
		// Key-based signing has no Fulcio cert, so issuer is empty
		r.Empty(sigInfo.Issuer)

		// Decode and verify the bundle is valid protobuf JSON
		bundleJSON, err := base64.StdEncoding.DecodeString(sigInfo.Value)
		r.NoError(err)

		var bundle protobundle.Bundle
		err = protojson.Unmarshal(bundleJSON, &bundle)
		r.NoError(err)

		r.Equal(v1alpha1.MediaTypeSigstoreBundle, bundle.GetMediaType())
		r.NotNil(bundle.GetVerificationMaterial())
		// Key-based: verification material should have a public key, not a certificate
		r.NotNil(bundle.GetVerificationMaterial().GetPublicKey())
		r.NotEmpty(bundle.GetVerificationMaterial().GetPublicKey().GetHint())
		// Should have a message signature
		r.NotNil(bundle.GetMessageSignature())
		r.NotEmpty(bundle.GetMessageSignature().GetSignature())
	})

	t.Run("sign with invalid digest hex returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		creds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		badDigest := descruntime.Digest{
			HashAlgorithm:          "SHA-256",
			NormalisationAlgorithm: "jsonNormalisation/v2",
			Value:                  "not-valid-hex!",
		}

		_, err := h.Sign(t.Context(), badDigest, offlineConfig(), creds)
		r.Error(err)
		r.Contains(err.Error(), "decode digest hex value")
	})

	t.Run("sign with invalid private key PEM returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		creds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: "not-a-pem",
		}

		_, err := h.Sign(t.Context(), sampleDigest(t), offlineConfig(), creds)
		r.Error(err)
		r.Contains(err.Error(), "private key")
	})

}

// ---- Verify tests ----

func Test_Handler_Verify(t *testing.T) {
	t.Parallel()

	t.Run("key-based sign-then-verify roundtrip (offline)", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)
		cfg := offlineConfig()

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		err = h.Verify(t.Context(), signed, cfg, verifyCreds)
		r.NoError(err)
	})

	t.Run("verification fails with wrong public key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		signKey := mustECDSAKey(t)
		wrongKey := mustECDSAKey(t)
		digest := sampleDigest(t)
		cfg := offlineConfig()

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, signKey),
		}

		sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &wrongKey.PublicKey),
		}

		err = h.Verify(t.Context(), signed, cfg, verifyCreds)
		r.Error(err)
		r.Contains(err.Error(), "verification failed")
	})

	t.Run("verification fails with tampered digest", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)
		cfg := offlineConfig()

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
		r.NoError(err)

		tamperedDigest := descruntime.Digest{
			HashAlgorithm:          digest.HashAlgorithm,
			NormalisationAlgorithm: digest.NormalisationAlgorithm,
			Value:                  hex.EncodeToString(make([]byte, 32)),
		}

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    tamperedDigest,
			Signature: sigInfo,
		}

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		err = h.Verify(t.Context(), signed, cfg, verifyCreds)
		r.Error(err)
		r.Contains(err.Error(), "verification failed")
	})

	t.Run("verification fails with invalid base64 bundle", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		signed := descruntime.Signature{
			Name:   "test-sig",
			Digest: sampleDigest(t),
			Signature: descruntime.SignatureInfo{
				Algorithm: v1alpha1.AlgorithmSigstore,
				MediaType: v1alpha1.MediaTypeSigstoreBundle,
				Value:     "not-valid-base64!!!",
			},
		}

		err := h.Verify(t.Context(), signed, offlineConfig(), map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &mustECDSAKey(t).PublicKey),
		})
		r.Error(err)
		r.Contains(err.Error(), "decode bundle base64")
	})

	t.Run("verification fails with invalid bundle JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		signed := descruntime.Signature{
			Name:   "test-sig",
			Digest: sampleDigest(t),
			Signature: descruntime.SignatureInfo{
				Algorithm: v1alpha1.AlgorithmSigstore,
				MediaType: v1alpha1.MediaTypeSigstoreBundle,
				Value:     base64.StdEncoding.EncodeToString([]byte("not-json")),
			},
		}

		err := h.Verify(t.Context(), signed, offlineConfig(), map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &mustECDSAKey(t).PublicKey),
		})
		r.Error(err)
		r.Contains(err.Error(), "unmarshal sigstore bundle")
	})

	t.Run("verification fails without any trusted material", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)

		signCfg := offlineConfig()
		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, signCfg, signCreds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		// Force TUF to fail by pointing at an invalid URL, ensuring no
		// network-dependent fallback. Without a public key, trusted root,
		// or reachable TUF mirror, verification must fail deterministically.
		verifyCfg := &v1alpha1.Config{
			SkipRekor:  true,
			TUFRootURL: "https://nonexistent-tuf.invalid",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

		err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{})
		r.Error(err)
		r.Contains(err.Error(), "resolve trusted material")
	})

	t.Run("public key derived from private key in credentials", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)
		cfg := offlineConfig()

		creds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, cfg, creds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		// Verify with same private key cred — public key should be derived
		err = h.Verify(t.Context(), signed, cfg, creds)
		r.NoError(err)
	})
}

// ---- Req 2: Rekor version tests ----

func Test_ConfigureTransparencyLog_RekorVersion(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.Config{
		RekorURL:     "https://custom-rekor.example.com",
		RekorVersion: 2,
	}

	var opts sign.BundleOptions
	configureTransparencyLog(&opts, cfg)

	r.Len(opts.TransparencyLogs, 1, "should add one transparency log")
}

func Test_ConfigureTransparencyLog_SkipRekor(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.Config{
		SkipRekor:    true,
		RekorVersion: 2,
	}

	var opts sign.BundleOptions
	configureTransparencyLog(&opts, cfg)

	r.Empty(opts.TransparencyLogs, "SkipRekor should prevent adding transparency logs")
}

func Test_ConfigureTimestampAuthority(t *testing.T) {
	t.Parallel()

	t.Run("TSAURL adds timestamp authority", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.Config{TSAURL: "https://custom-tsa.example.com/api/v1/timestamp"}

		var opts sign.BundleOptions
		configureTimestampAuthority(&opts, cfg)

		r.Len(opts.TimestampAuthorities, 1, "should add one timestamp authority")
	})

	t.Run("no TSA when TSAURL empty", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.Config{}

		var opts sign.BundleOptions
		configureTimestampAuthority(&opts, cfg)

		r.Empty(opts.TimestampAuthorities, "should not add timestamp authorities")
	})
}

// ---- Req 3: SigningConfig tests ----

func Test_ConfigureFromSigningConfig_ValidFile(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	signingConfigJSON := `{
		"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
		"caUrls": [
			{
				"url": "https://fulcio.example.com",
				"majorApiVersion": 1,
				"validFor": {"start": "2020-01-01T00:00:00Z"}
			}
		],
		"rekorTlogUrls": [
			{
				"url": "https://rekor-v2.example.com",
				"majorApiVersion": 2,
				"validFor": {"start": "2020-01-01T00:00:00Z"}
			}
		],
		"rekorTlogConfig": {"selector": "ANY"},
		"tsaUrls": [
			{
				"url": "https://tsa.example.com",
				"majorApiVersion": 1,
				"validFor": {"start": "2020-01-01T00:00:00Z"}
			}
		],
		"tsaConfig": {"selector": "ANY"}
	}`

	dir := t.TempDir()
	scPath := filepath.Join(dir, "signing_config.json")
	r.NoError(os.WriteFile(scPath, []byte(signingConfigJSON), 0o644))

	cfg := &v1alpha1.Config{
		SigningConfigPath: scPath,
	}

	var opts sign.BundleOptions
	opts.Context = t.Context()
	err := configureFromSigningConfig(&opts, cfg, "fake-oidc-token")
	r.NoError(err)

	r.NotNil(opts.CertificateProvider, "should configure Fulcio from signing config")
	r.NotNil(opts.CertificateProviderOptions, "should set OIDC token")
	r.Len(opts.TransparencyLogs, 1, "should configure Rekor from signing config")
	r.Len(opts.TimestampAuthorities, 1, "should configure TSA from signing config")
}

func Test_ConfigureFromSigningConfig_NoIDToken_SkipsFulcio(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	signingConfigJSON := `{
		"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
		"rekorTlogUrls": [
			{
				"url": "https://rekor.example.com",
				"majorApiVersion": 1,
				"validFor": {"start": "2020-01-01T00:00:00Z"}
			}
		],
		"rekorTlogConfig": {"selector": "ANY"}
	}`

	dir := t.TempDir()
	scPath := filepath.Join(dir, "signing_config.json")
	r.NoError(os.WriteFile(scPath, []byte(signingConfigJSON), 0o644))

	cfg := &v1alpha1.Config{
		SigningConfigPath: scPath,
	}

	var opts sign.BundleOptions
	opts.Context = t.Context()
	err := configureFromSigningConfig(&opts, cfg, "")
	r.NoError(err)

	r.Nil(opts.CertificateProvider, "should not configure Fulcio without ID token")
	r.Len(opts.TransparencyLogs, 1, "should configure Rekor")
}

func Test_ConfigureFromSigningConfig_InvalidPath(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.Config{
		SigningConfigPath: "/nonexistent/signing_config.json",
	}

	var opts sign.BundleOptions
	err := configureFromSigningConfig(&opts, cfg, "")
	r.Error(err)
	r.Contains(err.Error(), "load signing config")
}

// ---- Req 4: Identity verification tests ----

func Test_HasIdentityConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    *v1alpha1.Config
		expect bool
	}{
		{
			name:   "empty config",
			cfg:    &v1alpha1.Config{},
			expect: false,
		},
		{
			name:   "issuer set",
			cfg:    &v1alpha1.Config{ExpectedIssuer: "https://accounts.google.com"},
			expect: true,
		},
		{
			name:   "issuer regex set",
			cfg:    &v1alpha1.Config{ExpectedIssuerRegex: ".*google.*"},
			expect: true,
		},
		{
			name:   "SAN set",
			cfg:    &v1alpha1.Config{ExpectedSAN: "user@example.com"},
			expect: true,
		},
		{
			name:   "SAN regex set",
			cfg:    &v1alpha1.Config{ExpectedSANRegex: ".*@example\\.com"},
			expect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)
			r.Equal(tc.expect, hasIdentityConfig(tc.cfg))
		})
	}
}

// ---- Req 1: TUF fallback tests ----

func Test_ResolveTrustedMaterial_TUFRootURL_BadURL(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.Config{
		TUFRootURL: "https://nonexistent-tuf-repo.invalid",
	}

	_, err := resolveTrustedMaterial(t.Context(), cfg, map[string]string{})
	r.Error(err, "TUF fallback with invalid URL should fail")
}

// ---- resolveOfflineTrustedRoot tests ----

func Test_ResolveOfflineTrustedRoot(t *testing.T) {
	t.Parallel()

	t.Run("returns trusted root from credentials JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		cfg := &v1alpha1.Config{}
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveOfflineTrustedRoot(cfg, creds)
		r.NoError(err)
		r.NotNil(tm)
	})

	t.Run("returns trusted root from file path", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		dir := t.TempDir()
		trPath := filepath.Join(dir, "trusted_root.json")
		r.NoError(os.WriteFile(trPath, trustedRoot, 0o644))

		cfg := &v1alpha1.Config{TrustedRootPath: trPath}

		tm, err := resolveOfflineTrustedRoot(cfg, map[string]string{})
		r.NoError(err)
		r.NotNil(tm)
	})

	t.Run("returns nil when no offline source configured", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.Config{}

		tm, err := resolveOfflineTrustedRoot(cfg, map[string]string{})
		r.NoError(err)
		r.Nil(tm, "should return nil when no offline sources are available")
	})
}

// ---- ecdsaKeypair unit tests ----

func Test_ecdsaKeypair(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key := mustECDSAKey(t)
	kp, err := newECDSAKeypair(key)
	r.NoError(err)

	r.NotEmpty(kp.GetHint())
	r.Equal("ECDSA", kp.GetKeyAlgorithm())

	pubPEM, err := kp.GetPublicKeyPem()
	r.NoError(err)
	r.Contains(pubPEM, "BEGIN PUBLIC KEY")

	data := []byte("test data to sign")
	sig, digest, err := kp.SignData(t.Context(), data)
	r.NoError(err)
	r.NotEmpty(sig)
	r.NotEmpty(digest)

	// Verify the signature is valid ECDSA
	h := sha256.Sum256(data)
	r.Equal(h[:], digest)
	r.True(ecdsa.VerifyASN1(&key.PublicKey, digest, sig))
}

// ===========================================================================
// Keyless signing unit tests
// ===========================================================================

// ---- resolveKeypair keyless path ----

type mockTokenGetter struct {
	token  string
	err    error
	called bool
}

func (m *mockTokenGetter) GetIDToken() (string, error) {
	m.called = true
	return m.token, m.err
}

func Test_ResolveKeypair_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("OIDC token returns ephemeral keypair and token", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		creds := map[string]string{
			credentials.CredentialKeyOIDCToken: "fake-oidc-token",
		}

		kp, token, err := resolveKeypair(creds, nil)
		r.NoError(err)
		r.NotNil(kp, "should return an ephemeral keypair")
		r.Equal("fake-oidc-token", token)

		r.NotNil(kp.GetPublicKey(), "ephemeral keypair must have a public key")
		r.NotEmpty(kp.GetHint(), "ephemeral keypair must have a hint")
	})

	t.Run("no credentials returns ephemeral keypair with empty token", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		kp, token, err := resolveKeypair(map[string]string{}, nil)
		r.NoError(err)
		r.NotNil(kp)
		r.Empty(token, "without OIDC token, token string should be empty")
	})

	t.Run("private key takes precedence over OIDC token", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		key := mustECDSAKey(t)
		creds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
			credentials.CredentialKeyOIDCToken:     "some-token",
		}

		kp, token, err := resolveKeypair(creds, nil)
		r.NoError(err)
		r.NotNil(kp)
		r.Empty(token, "key-based mode should not return an OIDC token")

		// The keypair should be our ecdsaKeypair, not an ephemeral one
		_, isOurs := kp.(*ecdsaKeypair)
		r.True(isOurs, "should return ecdsaKeypair when private key is provided")
	})

	t.Run("TokenGetter is called when no credentials provide a token", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		tg := &mockTokenGetter{token: "getter-token"}
		kp, token, err := resolveKeypair(map[string]string{}, tg)
		r.NoError(err)
		r.NotNil(kp)
		r.Equal("getter-token", token)
		r.True(tg.called, "TokenGetter should have been invoked")
	})

	t.Run("credential token takes precedence over TokenGetter", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		tg := &mockTokenGetter{token: "getter-token"}
		creds := map[string]string{credentials.CredentialKeyOIDCToken: "cred-token"}
		kp, token, err := resolveKeypair(creds, tg)
		r.NoError(err)
		r.NotNil(kp)
		r.Equal("cred-token", token)
		r.False(tg.called, "TokenGetter should NOT be called when credential token exists")
	})

	t.Run("TokenGetter error is propagated", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		tg := &mockTokenGetter{err: fmt.Errorf("auth failed")}
		_, _, err := resolveKeypair(map[string]string{}, tg)
		r.Error(err)
		r.Contains(err.Error(), "auth failed")
	})
}

// ---- configureCertificateProvider tests ----

func Test_ConfigureCertificateProvider(t *testing.T) {
	t.Parallel()

	t.Run("with OIDC token configures Fulcio", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.Config{
			FulcioURL: "https://fulcio.example.com",
		}
		var opts sign.BundleOptions
		err := configureCertificateProvider(&opts, cfg, "my-token")
		r.NoError(err)

		r.NotNil(opts.CertificateProvider, "should configure Fulcio provider")
		r.NotNil(opts.CertificateProviderOptions, "should set provider options")
		r.Equal("my-token", opts.CertificateProviderOptions.IDToken)
	})

	t.Run("without OIDC token does not configure Fulcio", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.Config{
			FulcioURL: "https://fulcio.example.com",
		}
		var opts sign.BundleOptions
		err := configureCertificateProvider(&opts, cfg, "")
		r.NoError(err)

		r.Nil(opts.CertificateProvider, "should not configure Fulcio without token")
		r.Nil(opts.CertificateProviderOptions)
	})

	t.Run("empty FulcioURL with token returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.Config{}
		var opts sign.BundleOptions
		err := configureCertificateProvider(&opts, cfg, "my-token")
		r.Error(err)
		r.Contains(err.Error(), "FulcioURL must be set")

		r.Nil(opts.CertificateProvider)
	})
}

// ---- extractIssuer from Fulcio certificate ----

// makeFulcioCert creates a self-signed certificate with the Fulcio OIDC issuer
// extension (OID 1.3.6.1.4.1.57264.1.1) for testing extractIssuer.
// The value uses raw UTF-8 bytes (no ASN.1 wrapping), matching Fulcio's actual v1 encoding.
func makeFulcioCert(t *testing.T, issuer string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-fulcio-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
				Value: []byte(issuer),
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

// makeFulcioCertV2 creates a self-signed certificate with the v2 issuer
// extension (OID 1.3.6.1.4.1.57264.1.8), which uses proper ASN.1 encoding.
func makeFulcioCertV2(t *testing.T, issuer string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerDER, err := asn1.Marshal(issuer)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-fulcio-cert-v2"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
				Value: issuerDER,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

func Test_ExtractIssuer(t *testing.T) {
	t.Parallel()

	t.Run("extracts issuer from Fulcio certificate", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		certDER := makeFulcioCert(t, "https://accounts.google.com")

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{
						RawBytes: certDER,
					},
				},
			},
		}

		issuer := extractIssuer(bundle)
		r.Equal("https://accounts.google.com", issuer)
	})

	t.Run("extracts issuer with kubernetes URL", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		certDER := makeFulcioCert(t, "https://kubernetes.default.svc")

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{
						RawBytes: certDER,
					},
				},
			},
		}

		issuer := extractIssuer(bundle)
		r.Equal("https://kubernetes.default.svc", issuer)
	})

	t.Run("returns empty for bundle without certificate", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_PublicKey{
					PublicKey: &protocommon.PublicKeyIdentifier{Hint: "test-hint"},
				},
			},
		}

		r.Empty(extractIssuer(bundle))
	})

	t.Run("returns empty for nil verification material", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		r.Empty(extractIssuer(&protobundle.Bundle{}))
	})

	t.Run("returns empty for certificate without issuer extension", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "no-issuer-cert"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		r.NoError(err)

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{
						RawBytes: certDER,
					},
				},
			},
		}

		r.Empty(extractIssuer(bundle))
	})

	t.Run("extracts issuer from v2 OID extension", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		certDER := makeFulcioCertV2(t, "https://token.actions.githubusercontent.com")

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{
						RawBytes: certDER,
					},
				},
			},
		}

		r.Equal("https://token.actions.githubusercontent.com", extractIssuer(bundle))
	})

	t.Run("extracts issuer from raw v1 bytes", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		certDER := makeFulcioCert(t, "https://kubernetes.default.svc.cluster.local")

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{
						RawBytes: certDER,
					},
				},
			},
		}

		r.Equal("https://kubernetes.default.svc.cluster.local", extractIssuer(bundle))
	})

	t.Run("prefers v2 OID over v1 when both present", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		v2DER, err := asn1.Marshal("https://v2-issuer.example.com")
		require.NoError(t, err)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "dual-issuer-cert"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
					Value: []byte("https://v1-issuer.example.com"),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
					Value: v2DER,
				},
			},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		r.NoError(err)

		bundle := &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{
						RawBytes: certDER,
					},
				},
			},
		}

		r.Equal("https://v2-issuer.example.com", extractIssuer(bundle))
	})
}

// ---- buildPolicy keyless tests ----

func Test_BuildPolicy_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("without public key and with identity config uses certificate identity", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		digest := sampleDigest(t)
		digestBytes, err := hex.DecodeString(digest.Value)
		r.NoError(err)

		cfg := &v1alpha1.Config{
			ExpectedIssuer: "https://accounts.google.com",
			ExpectedSAN:    "user@example.com",
		}

		policy, err := buildPolicy(
			bytes.NewReader(digestBytes),
			map[string]string{},
			cfg,
		)
		r.NoError(err)
		// Policy should be non-zero (constructed successfully)
		r.NotEqual(verify.PolicyBuilder{}, policy)
	})

	t.Run("without public key and with issuer regex uses certificate identity", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		digest := sampleDigest(t)
		digestBytes, err := hex.DecodeString(digest.Value)
		r.NoError(err)

		cfg := &v1alpha1.Config{
			ExpectedIssuerRegex: ".*google.*",
			ExpectedSANRegex:    ".*@example\\.com",
		}

		policy, err := buildPolicy(
			bytes.NewReader(digestBytes),
			map[string]string{},
			cfg,
		)
		r.NoError(err)
		r.NotEqual(verify.PolicyBuilder{}, policy)
	})

	t.Run("without public key and without identity config returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		digest := sampleDigest(t)
		digestBytes, err := hex.DecodeString(digest.Value)
		r.NoError(err)

		cfg := &v1alpha1.Config{}

		_, err = buildPolicy(
			bytes.NewReader(digestBytes),
			map[string]string{},
			cfg,
		)
		r.Error(err)
		r.Contains(err.Error(), "keyless verification requires identity config")
	})

	t.Run("with public key always uses key policy regardless of identity config", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)
		digestBytes, err := hex.DecodeString(digest.Value)
		r.NoError(err)

		cfg := &v1alpha1.Config{
			ExpectedIssuer: "https://accounts.google.com",
			ExpectedSAN:    "user@example.com",
		}

		creds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		policy, err := buildPolicy(
			bytes.NewReader(digestBytes),
			creds,
			cfg,
		)
		r.NoError(err)
		r.NotEqual(verify.PolicyBuilder{}, policy)
	})
}

// ---- resolveTrustedMaterial keyless path ----

func Test_ResolveTrustedMaterial_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("trusted root from file path returns trusted material", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		dir := t.TempDir()
		trPath := filepath.Join(dir, "trusted_root.json")
		r.NoError(os.WriteFile(trPath, trustedRoot, 0o644))

		cfg := &v1alpha1.Config{
			TrustedRootPath: trPath,
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, map[string]string{})
		r.NoError(err)
		r.NotNil(tm, "should return trusted material from file")
	})

	t.Run("trusted root from credentials returns trusted material", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)

		cfg := &v1alpha1.Config{}
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, creds)
		r.NoError(err)
		r.NotNil(tm, "should return trusted material from credentials")
	})

	t.Run("trusted root from file with public key composes material", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		dir := t.TempDir()
		trPath := filepath.Join(dir, "trusted_root.json")
		r.NoError(os.WriteFile(trPath, trustedRoot, 0o644))

		key := mustECDSAKey(t)
		cfg := &v1alpha1.Config{
			TrustedRootPath: trPath,
		}
		creds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, creds)
		r.NoError(err)
		r.NotNil(tm)

		composed, ok := tm.(*composedTrustedMaterial)
		r.True(ok, "should return composedTrustedMaterial when both trusted root and key are present")

		// The composed material should delegate PublicKeyVerifier to the key material
		verifier, err := composed.PublicKeyVerifier("")
		r.NoError(err)
		r.NotNil(verifier)
	})

	t.Run("trusted root credentials take precedence over file path", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)

		cfg := &v1alpha1.Config{
			TrustedRootPath: "/nonexistent/should/not/be/read",
		}
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, creds)
		r.NoError(err)
		r.NotNil(tm, "credentials trusted root should take precedence")
	})
}

// ---- buildVerifier keyless tests ----

func Test_BuildVerifier_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("default config requires transparency log", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		cfg := &v1alpha1.Config{}
		v, err := buildVerifier(tm, cfg)
		r.NoError(err)
		r.NotNil(v, "should build verifier with tlog requirement")
	})

	t.Run("SkipRekor disables transparency log", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		cfg := &v1alpha1.Config{SkipRekor: true}
		v, err := buildVerifier(tm, cfg)
		r.NoError(err)
		r.NotNil(v, "should build verifier without tlog")
	})

	t.Run("TSAURL adds signed timestamp requirement", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		cfg := &v1alpha1.Config{TSAURL: "https://tsa.example.com/api/v1/timestamp"}
		v, err := buildVerifier(tm, cfg)
		r.NoError(err)
		r.NotNil(v, "should build verifier with TSA requirement")
	})

	t.Run("TSAURL adds signed timestamp requirement (alternate URL)", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		cfg := &v1alpha1.Config{TSAURL: "https://tsa.example.com"}
		v, err := buildVerifier(tm, cfg)
		r.NoError(err)
		r.NotNil(v, "should build verifier with TSA requirement")
	})

	t.Run("RekorVersion 2 without TSA uses no observer timestamps", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		cfg := &v1alpha1.Config{RekorVersion: 2}
		v, err := buildVerifier(tm, cfg)
		r.NoError(err)
		r.NotNil(v, "should build verifier for Rekor v2 without TSA")
	})

	t.Run("RekorVersion 2 with TSA uses observer timestamps", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		cfg := &v1alpha1.Config{RekorVersion: 2, TSAURL: "https://tsa.example.com/api/v1/timestamp"}
		v, err := buildVerifier(tm, cfg)
		r.NoError(err)
		r.NotNil(v, "should build verifier for Rekor v2 with TSA")
	})
}

// ---- Keyless sign flow (ephemeral keypair, offline) ----

func Test_Handler_Sign_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("keyless sign with invalid OIDC token returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		// An invalid (non-JWT) OIDC token should fail because sigstore-go
		// tries to extract the subject from the token during bundle creation.
		creds := map[string]string{
			credentials.CredentialKeyOIDCToken: "not-a-valid-jwt",
		}
		cfg := &v1alpha1.Config{
			FulcioURL: "https://fulcio.example.com",
			SkipRekor: true,
		}
		cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

		_, err := h.Sign(t.Context(), sampleDigest(t), cfg, creds)
		r.Error(err)
		r.Contains(err.Error(), "create sigstore bundle")
	})

	t.Run("keyless sign without OIDC token produces ephemeral bundle", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		// No private key and no OIDC token → ephemeral keypair, no Fulcio,
		// offline mode produces a valid bundle with a public key hint
		creds := map[string]string{}
		cfg := offlineConfig()

		sigInfo, err := h.Sign(t.Context(), sampleDigest(t), cfg, creds)
		r.NoError(err)
		r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
		r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
		r.NotEmpty(sigInfo.Value)

		bundleJSON, err := base64.StdEncoding.DecodeString(sigInfo.Value)
		r.NoError(err)

		var bundle protobundle.Bundle
		r.NoError(protojson.Unmarshal(bundleJSON, &bundle))

		vm := bundle.GetVerificationMaterial()
		r.NotNil(vm)
		r.NotNil(vm.GetPublicKey(), "ephemeral keypair should produce public key hint")
	})

	t.Run("keyless sign configures Fulcio when FulcioURL is set", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		token := "test-oidc-token"
		cfg := &v1alpha1.Config{
			FulcioURL: "https://fulcio.example.com",
			SkipRekor: true,
		}

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err := configureCertificateProvider(&opts, cfg, token)
		r.NoError(err)

		r.NotNil(opts.CertificateProvider)
		r.NotNil(opts.CertificateProviderOptions)
		r.Equal(token, opts.CertificateProviderOptions.IDToken)
	})
}

// ---- makeTrustedRootJSON helper ----

// makeTrustedRootJSON creates a minimal valid trusted root JSON for testing.
// This is a structurally valid protobuf-specs TrustedRoot with empty authority lists.
func makeTrustedRootJSON(t *testing.T) []byte {
	t.Helper()

	tr := map[string]any{
		"mediaType":              "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs":                  []any{},
		"certificateAuthorities": []any{},
		"ctlogs":                 []any{},
		"timestampAuthorities":   []any{},
	}

	data, err := json.Marshal(tr)
	require.NoError(t, err)
	return data
}

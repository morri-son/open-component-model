package handler

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
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

func defaultSignConfig() *v1alpha1.SignConfig {
	cfg := &v1alpha1.SignConfig{}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))
	return cfg
}

func defaultVerifyConfig() *v1alpha1.VerifyConfig {
	cfg := &v1alpha1.VerifyConfig{}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))
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
			defaultSignConfig(),
		)
		r.NoError(err)
		r.NotNil(id)
		r.Equal(v1alpha1.AlgorithmSigstore, id[IdentityAttributeAlgorithm])
		r.Equal("my-signature", id[IdentityAttributeSignature])

		idType := id.GetType()
		r.Equal(credentials.IdentityTypeSign, idType)
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

		id, err := h.GetVerifyingCredentialConsumerIdentity(t.Context(), sig, defaultVerifyConfig())
		r.NoError(err)
		r.NotNil(id)
		r.Equal(v1alpha1.AlgorithmSigstore, id[IdentityAttributeAlgorithm])
		r.Equal("my-signature", id[IdentityAttributeSignature])

		idType := id.GetType()
		r.Equal(credentials.IdentityTypeVerify, idType)
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

		_, err := h.GetVerifyingCredentialConsumerIdentity(t.Context(), sig, defaultVerifyConfig())
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
	badCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

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
	badCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

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

func Test_Handler_Sign_WrongConfigType(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	h := newHandler(t)

	// Pass a VerifyConfig type to Sign — should be rejected by the type guard.
	wrongCfg := &runtime.Raw{
		Data: []byte(`{}`),
	}
	wrongCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

	key := mustECDSAKey(t)
	creds := map[string]string{
		credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
	}

	_, err := h.Sign(t.Context(), sampleDigest(t), wrongCfg, creds)
	r.Error(err)
	r.Contains(err.Error(), "expected config type")
}

func Test_Handler_Verify_WrongConfigType(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	h := newHandler(t)

	// Pass a SignConfig type to Verify — should be rejected by the type guard.
	wrongCfg := &runtime.Raw{
		Data: []byte(`{}`),
	}
	wrongCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: sampleDigest(t),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     "dW51c2Vk",
		},
	}

	err := h.Verify(t.Context(), signed, wrongCfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "expected config type")
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

func offlineSignConfig() *v1alpha1.SignConfig {
	cfg := &v1alpha1.SignConfig{}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))
	return cfg
}

func offlineVerifyConfig() *v1alpha1.VerifyConfig {
	cfg := &v1alpha1.VerifyConfig{}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))
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

		sigInfo, err := h.Sign(t.Context(), sampleDigest(t), offlineSignConfig(), creds)
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

		_, err := h.Sign(t.Context(), badDigest, offlineSignConfig(), creds)
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

		_, err := h.Sign(t.Context(), sampleDigest(t), offlineSignConfig(), creds)
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

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
		r.NoError(err)
	})

	t.Run("verification fails with wrong public key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		signKey := mustECDSAKey(t)
		wrongKey := mustECDSAKey(t)
		digest := sampleDigest(t)

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, signKey),
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &wrongKey.PublicKey),
		}

		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
		r.Error(err)
		r.Contains(err.Error(), "verification failed")
	})

	t.Run("verification fails with tampered digest", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
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

		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
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

		err := h.Verify(t.Context(), signed, offlineVerifyConfig(), map[string]string{
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

		err := h.Verify(t.Context(), signed, offlineVerifyConfig(), map[string]string{
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

		signCfg := offlineSignConfig()
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
		verifyCfg := &v1alpha1.VerifyConfig{
			TUFRootURL: "https://nonexistent-tuf.invalid",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{})
		r.Error(err)
		r.Contains(err.Error(), "resolve trusted material")
	})

	t.Run("verification fails with invalid digest hex", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
		r.NoError(err)

		badDigest := descruntime.Digest{
			HashAlgorithm:          digest.HashAlgorithm,
			NormalisationAlgorithm: digest.NormalisationAlgorithm,
			Value:                  "not-valid-hex-gg$$",
		}

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    badDigest,
			Signature: sigInfo,
		}

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
		r.Error(err)
		r.Contains(err.Error(), "decode digest hex")
	})

	t.Run("verify requires explicit public key, not derived from private key", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		digest := sampleDigest(t)

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
		r.NoError(err)

		signed := descruntime.Signature{
			Name:      "test-sig",
			Digest:    digest,
			Signature: sigInfo,
		}

		// Verify with only private key cred — should fail because public key is not derived
		privateOnlyCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}
		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), privateOnlyCreds)
		r.Error(err)

		// Verify with explicit public key — should succeed
		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}
		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
		r.NoError(err)
	})

	t.Run("Ed25519 sign-then-verify roundtrip (offline)", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustEd25519Key(t)
		digest := sampleDigest(t)

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: mustPKCS8PrivateKeyPEM(t, key),
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
		r.NoError(err)
		r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
		r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)

		signed := descruntime.Signature{
			Name:      "test-sig-ed25519",
			Digest:    digest,
			Signature: sigInfo,
		}

		pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
		r.NoError(err)
		pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pubPEM,
		}

		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
		r.NoError(err)
	})

	t.Run("ECDSA P-384 sign-then-verify roundtrip (offline)", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		r.NoError(err)
		digest := sampleDigest(t)

		privDER, err := x509.MarshalECPrivateKey(key)
		r.NoError(err)
		privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

		signCreds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: privPEM,
		}

		sigInfo, err := h.Sign(t.Context(), digest, offlineSignConfig(), signCreds)
		r.NoError(err)
		r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
		r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)

		signed := descruntime.Signature{
			Name:      "test-sig-p384",
			Digest:    digest,
			Signature: sigInfo,
		}

		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		r.NoError(err)
		pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

		verifyCreds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pubPEM,
		}

		err = h.Verify(t.Context(), signed, offlineVerifyConfig(), verifyCreds)
		r.NoError(err)
	})
}

// ---- Req 2: Rekor version tests ----

func Test_ConfigureTransparencyLog_RekorVersion(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.SignConfig{
		RekorURL:     "https://custom-rekor.example.com",
		RekorVersion: 2,
	}

	var opts sign.BundleOptions
	configureTransparencyLog(&opts, cfg)

	r.Len(opts.TransparencyLogs, 1, "should add one transparency log")
}

func Test_ConfigureTransparencyLog_NoRekorURL(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.SignConfig{
		RekorVersion: 2,
	}

	var opts sign.BundleOptions
	configureTransparencyLog(&opts, cfg)

	r.Empty(opts.TransparencyLogs, "empty RekorURL should prevent adding transparency logs")
}

func Test_ConfigureTransparencyLog_DefaultVersion(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := &v1alpha1.SignConfig{
		RekorURL: "https://rekor.example.com",
	}

	var opts sign.BundleOptions
	configureTransparencyLog(&opts, cfg)

	r.Len(opts.TransparencyLogs, 1, "should add transparency log with default version")
}

func Test_KeypairFromPrivateKey_UnsupportedType(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	_, err = keypairFromPrivateKey(rsaKey)
	r.Error(err)
	r.Contains(err.Error(), "unsupported private key type")
}

func Test_ConfigureTimestampAuthority(t *testing.T) {
	t.Parallel()

	t.Run("TSAURL adds timestamp authority", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.SignConfig{TSAURL: "https://custom-tsa.example.com/api/v1/timestamp"}

		var opts sign.BundleOptions
		configureTimestampAuthority(&opts, cfg)

		r.Len(opts.TimestampAuthorities, 1, "should add one timestamp authority")
	})

	t.Run("no TSA when TSAURL empty", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.SignConfig{}

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

	cfg := &v1alpha1.SignConfig{
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

	cfg := &v1alpha1.SignConfig{
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

	cfg := &v1alpha1.SignConfig{
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
		cfg    *v1alpha1.VerifyConfig
		expect bool
	}{
		{
			name:   "empty config",
			cfg:    &v1alpha1.VerifyConfig{},
			expect: false,
		},
		{
			name:   "issuer set",
			cfg:    &v1alpha1.VerifyConfig{ExpectedIssuer: "https://accounts.google.com"},
			expect: true,
		},
		{
			name:   "issuer regex set",
			cfg:    &v1alpha1.VerifyConfig{ExpectedIssuerRegex: ".*google.*"},
			expect: true,
		},
		{
			name:   "SAN set",
			cfg:    &v1alpha1.VerifyConfig{ExpectedSAN: "user@example.com"},
			expect: true,
		},
		{
			name:   "SAN regex set",
			cfg:    &v1alpha1.VerifyConfig{ExpectedSANRegex: ".*@example\\.com"},
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

	cfg := &v1alpha1.VerifyConfig{
		TUFRootURL: "https://nonexistent-tuf-repo.invalid",
	}

	_, err := resolveTrustedMaterial(t.Context(), cfg, map[string]string{}, nil)
	r.Error(err, "TUF without initial root should fail")
	r.Contains(err.Error(), "TUFInitialRoot is required")
}

// ---- resolveOfflineTrustedRoot tests ----

func Test_ResolveOfflineTrustedRoot(t *testing.T) {
	t.Parallel()

	t.Run("returns trusted root from credentials JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveOfflineTrustedRoot(creds)
		r.NoError(err)
		r.NotNil(tm)
	})

	t.Run("returns nil when no offline source configured", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		tm, err := resolveOfflineTrustedRoot(map[string]string{})
		r.NoError(err)
		r.Nil(tm, "should return nil when no offline sources are available")
	})

	t.Run("returns error for corrupted trusted root JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: `{not valid json`,
		}

		_, err := resolveOfflineTrustedRoot(creds)
		r.Error(err)
	})
}

// ---- ecdsaKeypair unit tests ----

func Test_ecdsaKeypair(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key := mustECDSAKey(t)
	kp, err := newECDSAKeypair(key)
	r.NoError(err)

	// Algorithm details must match PKIX_ECDSA_P256_SHA_256, identical to
	// sigstore-go's EphemeralKeypair defaults.
	r.Equal(protocommon.HashAlgorithm_SHA2_256, kp.GetHashAlgorithm())
	r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
	r.Equal("ECDSA", kp.GetKeyAlgorithm())

	// Hint must match sigstore-go's computation: base64(sha256(DER public key)).
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r.NoError(err)
	expectedHash := sha256.Sum256(pubDER)
	expectedHint := []byte(base64.StdEncoding.EncodeToString(expectedHash[:]))
	r.Equal(expectedHint, kp.GetHint())

	pubPEM, err := kp.GetPublicKeyPem()
	r.NoError(err)
	r.Contains(pubPEM, "BEGIN PUBLIC KEY")

	// Verify SignData via signature.LoadVerifierWithOpts, mirroring sigstore-go's
	// own keys_test.go pattern rather than raw ecdsa.VerifyASN1.
	data := []byte("test data to sign")
	sig, digest, err := kp.SignData(t.Context(), data)
	r.NoError(err)
	r.NotEmpty(sig)

	h := sha256.Sum256(data)
	r.Equal(h[:], digest)

	verifier, err := signature.LoadVerifierWithOpts(kp.GetPublicKey(), options.WithHash(crypto.SHA256))
	r.NoError(err)
	r.NoError(verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)))
}

func mustEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

func mustPKCS8PrivateKeyPEM(t *testing.T, key interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func Test_ecdsaKeypair_P384(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	r.NoError(err)
	kp, err := newECDSAKeypair(key)
	r.NoError(err)

	r.Equal(protocommon.HashAlgorithm_SHA2_384, kp.GetHashAlgorithm())
	r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, kp.GetSigningAlgorithm())
	r.Equal("ECDSA", kp.GetKeyAlgorithm())

	pubPEM, err := kp.GetPublicKeyPem()
	r.NoError(err)
	r.Contains(pubPEM, "BEGIN PUBLIC KEY")

	data := []byte("test data for P-384")
	sig, digest, err := kp.SignData(t.Context(), data)
	r.NoError(err)
	r.NotEmpty(sig)
	r.NotEmpty(digest)

	verifier, err := signature.LoadVerifierWithOpts(kp.GetPublicKey(), options.WithHash(crypto.SHA384))
	r.NoError(err)
	r.NoError(verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)))
}

func Test_ecdsaKeypair_P521(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	r.NoError(err)
	kp, err := newECDSAKeypair(key)
	r.NoError(err)

	r.Equal(protocommon.HashAlgorithm_SHA2_512, kp.GetHashAlgorithm())
	r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, kp.GetSigningAlgorithm())
	r.Equal("ECDSA", kp.GetKeyAlgorithm())

	pubPEM, err := kp.GetPublicKeyPem()
	r.NoError(err)
	r.Contains(pubPEM, "BEGIN PUBLIC KEY")

	data := []byte("test data for P-521")
	sig, digest, err := kp.SignData(t.Context(), data)
	r.NoError(err)
	r.NotEmpty(sig)
	r.NotEmpty(digest)

	verifier, err := signature.LoadVerifierWithOpts(kp.GetPublicKey(), options.WithHash(crypto.SHA512))
	r.NoError(err)
	r.NoError(verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)))
}

func Test_ed25519Keypair(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key := mustEd25519Key(t)
	kp, err := newEd25519Keypair(key)
	r.NoError(err)

	r.Equal(protocommon.HashAlgorithm_SHA2_512, kp.GetHashAlgorithm())
	r.Equal(protocommon.PublicKeyDetails_PKIX_ED25519, kp.GetSigningAlgorithm())
	r.Equal("Ed25519", kp.GetKeyAlgorithm())

	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	r.NoError(err)
	expectedHash := sha256.Sum256(pubDER)
	r.Equal([]byte(base64.StdEncoding.EncodeToString(expectedHash[:])), kp.GetHint())

	pubPEM, err := kp.GetPublicKeyPem()
	r.NoError(err)
	r.Contains(pubPEM, "BEGIN PUBLIC KEY")

	data := []byte("test data for Ed25519")
	sig, returned, err := kp.SignData(t.Context(), data)
	r.NoError(err)
	r.NotEmpty(sig)
	r.Equal(data, returned, "Ed25519 SignData should return raw data, not a digest")

	verifier, err := signature.LoadVerifierWithOpts(kp.GetPublicKey(), options.WithHash(crypto.Hash(0)))
	r.NoError(err)
	r.NoError(verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)))
}

func Test_keypairFromPrivateKey(t *testing.T) {
	t.Parallel()

	t.Run("P-256 returns ecdsaKeypair", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustECDSAKey(t)
		kp, err := keypairFromPrivateKey(key)
		r.NoError(err)
		_, ok := kp.(*ecdsaKeypair)
		r.True(ok)
		r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
	})

	t.Run("P-384 returns ecdsaKeypair", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		r.NoError(err)
		kp, err := keypairFromPrivateKey(key)
		r.NoError(err)
		_, ok := kp.(*ecdsaKeypair)
		r.True(ok)
		r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, kp.GetSigningAlgorithm())
	})

	t.Run("P-521 returns ecdsaKeypair", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		r.NoError(err)
		kp, err := keypairFromPrivateKey(key)
		r.NoError(err)
		_, ok := kp.(*ecdsaKeypair)
		r.True(ok)
		r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, kp.GetSigningAlgorithm())
	})

	t.Run("Ed25519 returns ed25519Keypair", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		key := mustEd25519Key(t)
		kp, err := keypairFromPrivateKey(key)
		r.NoError(err)
		_, ok := kp.(*ed25519Keypair)
		r.True(ok)
		r.Equal(protocommon.PublicKeyDetails_PKIX_ED25519, kp.GetSigningAlgorithm())
	})
}

func Test_ResolveKeypair_KeyBased(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pemFunc func(t *testing.T) string
		check   func(t *testing.T, kp sign.Keypair)
	}{
		{
			name: "P-256 EC PRIVATE KEY",
			pemFunc: func(t *testing.T) string {
				return pemEncodePrivateKey(t, mustECDSAKey(t))
			},
			check: func(t *testing.T, kp sign.Keypair) {
				t.Helper()
				r := require.New(t)
				_, ok := kp.(*ecdsaKeypair)
				r.True(ok)
				r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
			},
		},
		{
			name: "P-384 EC PRIVATE KEY",
			pemFunc: func(t *testing.T) string {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				der, err := x509.MarshalECPrivateKey(key)
				require.NoError(t, err)
				return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
			},
			check: func(t *testing.T, kp sign.Keypair) {
				t.Helper()
				r := require.New(t)
				_, ok := kp.(*ecdsaKeypair)
				r.True(ok)
				r.Equal(protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, kp.GetSigningAlgorithm())
			},
		},
		{
			name: "Ed25519 PKCS8",
			pemFunc: func(t *testing.T) string {
				return mustPKCS8PrivateKeyPEM(t, mustEd25519Key(t))
			},
			check: func(t *testing.T, kp sign.Keypair) {
				t.Helper()
				r := require.New(t)
				_, ok := kp.(*ed25519Keypair)
				r.True(ok)
				r.Equal(protocommon.PublicKeyDetails_PKIX_ED25519, kp.GetSigningAlgorithm())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)
			creds := map[string]string{
				credentials.CredentialKeyPrivateKeyPEM: tc.pemFunc(t),
			}
			kp, token, err := resolveKeypair(creds)
			r.NoError(err)
			r.NotNil(kp)
			r.Empty(token)
			tc.check(t, kp)
		})
	}
}

// ===========================================================================
// Keyless signing unit tests
// ===========================================================================

// ---- resolveKeypair keyless path ----

func Test_ResolveKeypair_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("OIDC token returns ephemeral keypair and token", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		creds := map[string]string{
			credentials.CredentialKeyOIDCToken: "fake-oidc-token",
		}

		kp, token, err := resolveKeypair(creds)
		r.NoError(err)
		r.NotNil(kp, "should return an ephemeral keypair")
		r.Equal("fake-oidc-token", token)

		r.NotNil(kp.GetPublicKey(), "ephemeral keypair must have a public key")
		r.NotEmpty(kp.GetHint(), "ephemeral keypair must have a hint")
	})

	t.Run("no credentials returns ephemeral keypair with empty token", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		kp, token, err := resolveKeypair(map[string]string{})
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

		kp, token, err := resolveKeypair(creds)
		r.NoError(err)
		r.NotNil(kp)
		r.Empty(token, "key-based mode should not return an OIDC token")

		// The keypair should be our ecdsaKeypair, not an ephemeral one
		_, isOurs := kp.(*ecdsaKeypair)
		r.True(isOurs, "should return ecdsaKeypair when private key is provided")
	})
}

// ---- configureCertificateProvider tests ----

func Test_ConfigureCertificateProvider(t *testing.T) {
	t.Parallel()

	t.Run("with OIDC token configures Fulcio", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.SignConfig{
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

		cfg := &v1alpha1.SignConfig{
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

		cfg := &v1alpha1.SignConfig{}
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

		cfg := &v1alpha1.VerifyConfig{
			ExpectedIssuer: "https://accounts.google.com",
			ExpectedSAN:    "user@example.com",
		}

		policy, err := buildPolicy(
			bytes.NewReader(digestBytes),
			nil,
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

		cfg := &v1alpha1.VerifyConfig{
			ExpectedIssuerRegex: ".*google.*",
			ExpectedSANRegex:    ".*@example\\.com",
		}

		policy, err := buildPolicy(
			bytes.NewReader(digestBytes),
			nil,
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

		cfg := &v1alpha1.VerifyConfig{}

		_, err = buildPolicy(
			bytes.NewReader(digestBytes),
			nil,
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

		cfg := &v1alpha1.VerifyConfig{
			ExpectedIssuer: "https://accounts.google.com",
			ExpectedSAN:    "user@example.com",
		}

		policy, err := buildPolicy(
			bytes.NewReader(digestBytes),
			&key.PublicKey,
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

		cfg := &v1alpha1.VerifyConfig{
			TrustedRootPath: trPath,
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, map[string]string{}, nil)
		r.NoError(err)
		r.NotNil(tm, "should return trusted material from file")
	})

	t.Run("trusted root from credentials returns trusted material", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)

		cfg := &v1alpha1.VerifyConfig{}
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, creds, nil)
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
		cfg := &v1alpha1.VerifyConfig{
			TrustedRootPath: trPath,
		}
		creds := map[string]string{
			credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, creds, &key.PublicKey)
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

		cfg := &v1alpha1.VerifyConfig{
			TrustedRootPath: "/nonexistent/should/not/be/read",
		}
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveTrustedMaterial(t.Context(), cfg, creds, nil)
		r.NoError(err)
		r.NotNil(tm, "credentials trusted root should take precedence")
	})
}

// ---- buildVerifier keyless tests ----

func Test_BuildVerifier_Keyless(t *testing.T) {
	t.Parallel()

	t.Run("trusted material with Rekor logs requires transparency log", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootWithRekorJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)
		r.Greater(len(tm.RekorLogs()), 0, "trusted material should have Rekor log entries")

		v, err := buildVerifier(tm, false)
		r.NoError(err)
		r.NotNil(v, "should build verifier with transparency log requirement")
	})

	t.Run("empty Rekor logs auto-detects no transparency log requirement", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		v, err := buildVerifier(tm, false)
		r.NoError(err)
		r.NotNil(v, "should build verifier without tlog when no Rekor logs in trusted material")
	})

}

func Test_BuildVerifier_KeyBased(t *testing.T) {
	t.Parallel()

	t.Run("key-based with Rekor logs enables transparency log", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootWithRekorJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)
		r.Greater(len(tm.RekorLogs()), 0, "trusted material should have Rekor log entries")

		v, err := buildVerifier(tm, true)
		r.NoError(err)
		r.NotNil(v, "should build verifier with transparency log for key-based when Rekor logs present")
	})

	t.Run("key-based without Rekor logs auto-detects", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)

		v, err := buildVerifier(tm, true)
		r.NoError(err)
		r.NotNil(v, "should build verifier without tlog for key-based when no Rekor logs")
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
		cfg := &v1alpha1.SignConfig{
			FulcioURL: "https://fulcio.example.com",
		}
		cfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

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
		cfg := offlineSignConfig()

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

}

// ---- makeTrustedRoot helpers ----

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

// makeTrustedRootWithRekorJSON creates a trusted root JSON with a Rekor transparency
// log entry so that len(trustedMaterial.RekorLogs()) > 0 is true.
func makeTrustedRootWithRekorJSON(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	logIDHash := sha256.Sum256(pubDER)

	tr := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": []any{
			map[string]any{
				"baseUrl":       "https://rekor.example.com",
				"hashAlgorithm": "SHA2_256",
				"logId": map[string]any{
					"keyId": base64.StdEncoding.EncodeToString(logIDHash[:]),
				},
				"publicKey": map[string]any{
					"rawBytes":   base64.StdEncoding.EncodeToString(pubDER),
					"keyDetails": "PKIX_ECDSA_P256_SHA_256",
					"validFor": map[string]any{
						"start": "2020-01-01T00:00:00Z",
					},
				},
			},
		},
		"certificateAuthorities": []any{},
		"ctlogs":                 []any{},
		"timestampAuthorities":   []any{},
	}

	data, err := json.Marshal(tr)
	require.NoError(t, err)
	return data
}

// ---- configureFromSigningConfig error path tests ----

func Test_ConfigureFromSigningConfig_ExpiredServices(t *testing.T) {
	t.Parallel()

	t.Run("expired Fulcio CA returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		signingConfigJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"caUrls": [
				{
					"url": "https://fulcio.example.com",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}
				}
			]
		}`

		dir := t.TempDir()
		scPath := filepath.Join(dir, "signing_config.json")
		r.NoError(os.WriteFile(scPath, []byte(signingConfigJSON), 0o644))

		cfg := &v1alpha1.SignConfig{SigningConfigPath: scPath}

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err := configureFromSigningConfig(&opts, cfg, "fake-oidc-token")
		r.Error(err)
		r.Contains(err.Error(), "select fulcio service")
	})

	t.Run("expired Rekor service returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		signingConfigJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"rekorTlogUrls": [
				{
					"url": "https://rekor.example.com",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}
				}
			],
			"rekorTlogConfig": {"selector": "ANY"}
		}`

		dir := t.TempDir()
		scPath := filepath.Join(dir, "signing_config.json")
		r.NoError(os.WriteFile(scPath, []byte(signingConfigJSON), 0o644))

		cfg := &v1alpha1.SignConfig{SigningConfigPath: scPath}

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err := configureFromSigningConfig(&opts, cfg, "")
		r.Error(err)
		r.Contains(err.Error(), "select rekor service")
	})

	t.Run("expired TSA service returns error", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		signingConfigJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"tsaUrls": [
				{
					"url": "https://tsa.example.com",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}
				}
			],
			"tsaConfig": {"selector": "ANY"}
		}`

		dir := t.TempDir()
		scPath := filepath.Join(dir, "signing_config.json")
		r.NoError(os.WriteFile(scPath, []byte(signingConfigJSON), 0o644))

		cfg := &v1alpha1.SignConfig{SigningConfigPath: scPath}

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err := configureFromSigningConfig(&opts, cfg, "")
		r.Error(err)
		r.Contains(err.Error(), "select tsa service")
	})
}

// ---- validateConfig tests ----

func Test_ValidateConfig(t *testing.T) {
	t.Parallel()

	t.Run("RekorVersion 0 is valid", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		r.NoError(validateSignConfig(&v1alpha1.SignConfig{RekorVersion: 0}))
	})

	t.Run("RekorVersion 1 is valid", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		r.NoError(validateSignConfig(&v1alpha1.SignConfig{RekorVersion: 1}))
	})

	t.Run("RekorVersion 2 is valid", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		r.NoError(validateSignConfig(&v1alpha1.SignConfig{RekorVersion: 2}))
	})

	t.Run("RekorVersion 3 is rejected", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		err := validateSignConfig(&v1alpha1.SignConfig{RekorVersion: 3})
		r.Error(err)
		r.Contains(err.Error(), "unsupported RekorVersion 3")
	})

	t.Run("invalid RekorVersion blocks sign", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		h := newHandler(t)

		key := mustECDSAKey(t)
		creds := map[string]string{
			credentials.CredentialKeyPrivateKeyPEM: pemEncodePrivateKey(t, key),
		}
		cfg := &v1alpha1.SignConfig{
			RekorVersion: 3,
		}
		cfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

		_, err := h.Sign(t.Context(), sampleDigest(t), cfg, creds)
		r.Error(err)
		r.Contains(err.Error(), "unsupported RekorVersion 3")
	})
}

// ---- TUF failure with public key fallback ----

func Test_ResolveTrustedMaterial_TUFFailure_PublicKeyFallback(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	key := mustECDSAKey(t)
	cfg := &v1alpha1.VerifyConfig{
		TUFRootURL: "https://nonexistent-tuf-repo.invalid",
	}
	creds := map[string]string{
		credentials.CredentialKeyPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	}

	// TUF requires a pinned initial root — without it, resolution fails
	// even when a public key is available (TUF resolution happens unconditionally).
	tm, err := resolveTrustedMaterial(t.Context(), cfg, creds, &key.PublicKey)

	// Missing TUFInitialRoot causes resolveTrustedRoot to fail, which propagates up.
	// Even though we have a public key, the TUF error takes precedence.
	r.Error(err, "TUF failure should propagate even when public key is available")
	r.Contains(err.Error(), "TUFInitialRoot is required")
	r.Nil(tm)
}

// ---- buildVerifier SCT tests ----

// makeTrustedRootWithCTLogJSON creates a trusted root JSON with a CT log entry
// so that len(trustedMaterial.CTLogs()) > 0 is true.
func makeTrustedRootWithCTLogJSON(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	logIDHash := sha256.Sum256(pubDER)

	tr := map[string]any{
		"mediaType":              "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs":                  []any{},
		"certificateAuthorities": []any{},
		"ctlogs": []any{
			map[string]any{
				"baseUrl":       "https://ctfe.example.com",
				"hashAlgorithm": "SHA2_256",
				"logId": map[string]any{
					"keyId": base64.StdEncoding.EncodeToString(logIDHash[:]),
				},
				"publicKey": map[string]any{
					"rawBytes":   base64.StdEncoding.EncodeToString(pubDER),
					"keyDetails": "PKIX_ECDSA_P256_SHA_256",
					"validFor": map[string]any{
						"start": "2020-01-01T00:00:00Z",
					},
				},
			},
		},
		"timestampAuthorities": []any{},
	}

	data, err := json.Marshal(tr)
	require.NoError(t, err)
	return data
}

func Test_BuildVerifier_SCT(t *testing.T) {
	t.Parallel()

	t.Run("keyless with CT logs enables SCT verification", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootWithCTLogJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)
		r.Greater(len(tm.CTLogs()), 0, "trusted material should have CT log entries")

		v, err := buildVerifier(tm, false)
		r.NoError(err)
		r.NotNil(v, "should build verifier with SCT requirement for keyless")
	})

	t.Run("key-based skips SCT even with CT logs", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootWithCTLogJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)
		r.Greater(len(tm.CTLogs()), 0, "trusted material should have CT log entries")

		v, err := buildVerifier(tm, true)
		r.NoError(err)
		r.NotNil(v, "should build verifier without SCT for key-based")
	})
}

// ---- hasExplicitEndpoints tests ----

func Test_HasExplicitEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *v1alpha1.SignConfig
		expected bool
	}{
		{
			name:     "empty config",
			cfg:      &v1alpha1.SignConfig{},
			expected: false,
		},
		{
			name:     "FulcioURL set",
			cfg:      &v1alpha1.SignConfig{FulcioURL: "https://fulcio.example.com"},
			expected: true,
		},
		{
			name:     "RekorURL set",
			cfg:      &v1alpha1.SignConfig{RekorURL: "https://rekor.example.com"},
			expected: true,
		},
		{
			name:     "TSAURL set",
			cfg:      &v1alpha1.SignConfig{TSAURL: "https://tsa.example.com"},
			expected: true,
		},
		{
			name: "all URLs set",
			cfg: &v1alpha1.SignConfig{
				FulcioURL: "https://fulcio.example.com",
				RekorURL:  "https://rekor.example.com",
				TSAURL:    "https://tsa.example.com",
			},
			expected: true,
		},
		{
			name:     "SigningConfigPath does not count as explicit endpoint",
			cfg:      &v1alpha1.SignConfig{SigningConfigPath: "/path/to/config.json"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)
			r.Equal(tt.expected, hasExplicitEndpoints(tt.cfg))
		})
	}
}

// ---- applySigningConfig tests ----

func Test_ApplySigningConfig(t *testing.T) {
	t.Parallel()

	t.Run("configures Fulcio when idToken present", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		scJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"caUrls": [
				{
					"url": "https://fulcio.sigstore.dev",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z"}
				}
			],
			"rekorTlogUrls": [
				{
					"url": "https://rekor.sigstore.dev",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z"}
				}
			]
		}`

		sc, err := root.NewSigningConfigFromJSON([]byte(scJSON))
		r.NoError(err)

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err = applySigningConfig(&opts, sc, "test-token")
		r.NoError(err)
		r.NotNil(opts.CertificateProvider, "Fulcio should be configured")
		r.NotNil(opts.CertificateProviderOptions, "CertificateProviderOptions should be set")
		r.Equal("test-token", opts.CertificateProviderOptions.IDToken)
		r.Len(opts.TransparencyLogs, 1, "Rekor should be configured")
	})

	t.Run("skips Fulcio when idToken empty", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		scJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"caUrls": [
				{
					"url": "https://fulcio.sigstore.dev",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z"}
				}
			],
			"rekorTlogUrls": [
				{
					"url": "https://rekor.sigstore.dev",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z"}
				}
			]
		}`

		sc, err := root.NewSigningConfigFromJSON([]byte(scJSON))
		r.NoError(err)

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err = applySigningConfig(&opts, sc, "")
		r.NoError(err)
		r.Nil(opts.CertificateProvider, "Fulcio should not be configured without token")
		r.Len(opts.TransparencyLogs, 1, "Rekor should still be configured")
	})

	t.Run("configures TSA when available", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		scJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"tsaUrls": [
				{
					"url": "https://tsa.sigstore.dev",
					"majorApiVersion": 1,
					"validFor": {"start": "2020-01-01T00:00:00Z"}
				}
			]
		}`

		sc, err := root.NewSigningConfigFromJSON([]byte(scJSON))
		r.NoError(err)

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err = applySigningConfig(&opts, sc, "")
		r.NoError(err)
		r.Len(opts.TimestampAuthorities, 1, "TSA should be configured")
	})

	t.Run("empty signing config produces no services", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		scJSON := `{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json"
		}`

		sc, err := root.NewSigningConfigFromJSON([]byte(scJSON))
		r.NoError(err)

		var opts sign.BundleOptions
		opts.Context = t.Context()
		err = applySigningConfig(&opts, sc, "")
		r.NoError(err)
		r.Nil(opts.CertificateProvider)
		r.Empty(opts.TransparencyLogs)
		r.Empty(opts.TimestampAuthorities)
	})
}

// ---- buildVerifier with TSA from trusted material tests ----

// makeTrustedRootWithTSAJSON creates a trusted root JSON with a timestamp authority entry.
func makeTrustedRootWithTSAJSON(t *testing.T) []byte {
	t.Helper()

	key := mustECDSAKey(t)
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	tr := map[string]any{
		"mediaType":              "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs":                  []any{},
		"certificateAuthorities": []any{},
		"ctlogs":                 []any{},
		"timestampAuthorities": []any{
			map[string]any{
				"subject": map[string]any{
					"organization": "Test",
					"commonName":   "Test TSA",
				},
				"uri": "https://tsa.example.com",
				"certChain": map[string]any{
					"certificates": []any{
						map[string]any{
							"rawBytes": base64.StdEncoding.EncodeToString(certDER),
						},
					},
				},
				"validFor": map[string]any{
					"start": "2020-01-01T00:00:00Z",
				},
			},
		},
	}

	data, err := json.Marshal(tr)
	require.NoError(t, err)
	return data
}

func Test_BuildVerifier_TSAFromTrustedMaterial(t *testing.T) {
	t.Parallel()

	t.Run("TSA in material without explicit TSAURL uses observer timestamps", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootWithTSAJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)
		r.Greater(len(tm.TimestampingAuthorities()), 0, "trusted material should have TSA")

		v, err := buildVerifier(tm, false)
		r.NoError(err)
		r.NotNil(v, "should build verifier with observer timestamps from material TSA")
	})

	t.Run("no TSA anywhere uses integrated timestamps", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		tm, err := root.NewTrustedRootFromJSON(trustedRoot)
		r.NoError(err)
		r.Empty(tm.TimestampingAuthorities(), "trusted material should not have TSA")

		v, err := buildVerifier(tm, false)
		r.NoError(err)
		r.NotNil(v, "should build verifier with integrated timestamps")
	})
}

// ---- resolveTrustedRootExplicit tests ----

func Test_ResolveTrustedRootExplicit(t *testing.T) {
	t.Parallel()

	t.Run("returns trusted root from credentials JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		tm, err := resolveTrustedRootExplicit(t.Context(), &v1alpha1.VerifyConfig{}, creds)
		r.NoError(err)
		r.NotNil(tm, "should resolve trusted root from credentials")
	})

	t.Run("returns trusted root from TrustedRootPath", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		dir := t.TempDir()
		trPath := filepath.Join(dir, "trusted_root.json")
		r.NoError(os.WriteFile(trPath, trustedRoot, 0o644))

		cfg := &v1alpha1.VerifyConfig{TrustedRootPath: trPath}
		tm, err := resolveTrustedRootExplicit(t.Context(), cfg, map[string]string{})
		r.NoError(err)
		r.NotNil(tm, "should resolve trusted root from file path")
	})

	t.Run("returns nil when no source configured", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		tm, err := resolveTrustedRootExplicit(t.Context(), &v1alpha1.VerifyConfig{}, map[string]string{})
		r.NoError(err)
		r.Nil(tm, "should return nil when no source is configured")
	})

	t.Run("TUFRootURL without TUFInitialRoot fails", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		cfg := &v1alpha1.VerifyConfig{TUFRootURL: "https://tuf.example.com"}
		tm, err := resolveTrustedRootExplicit(t.Context(), cfg, map[string]string{})
		r.Error(err)
		r.Contains(err.Error(), "TUFInitialRoot is required")
		r.Nil(tm)
	})

	t.Run("credentials take precedence over TrustedRootPath", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)

		trustedRoot := makeTrustedRootJSON(t)
		creds := map[string]string{
			credentials.CredentialKeyTrustedRootJSON: string(trustedRoot),
		}

		cfg := &v1alpha1.VerifyConfig{TrustedRootPath: "/nonexistent/path"}
		tm, err := resolveTrustedRootExplicit(t.Context(), cfg, creds)
		r.NoError(err)
		r.NotNil(tm, "credentials should take precedence over config path")
	})
}

// ---- resolveTrustedRoot auto-discovery tests ----
// (Tests requiring network access for TUF auto-discovery are in integration tests.)

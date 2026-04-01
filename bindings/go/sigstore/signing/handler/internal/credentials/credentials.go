package credentials

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"ocm.software/open-component-model/bindings/go/runtime"
)

var (
	IdentityTypeSign   = runtime.NewVersionedType("SigstoreSigningConfiguration", "v1alpha1")
	IdentityTypeVerify = runtime.NewVersionedType("SigstoreVerificationConfiguration", "v1alpha1")
)

// Credential keys.
//
//nolint:gosec // these are not secrets
const (
	CredentialKeyPrivateKeyPEM       = "private_key_pem" // inline private key PEM (ECDSA P-256/384/521 or Ed25519)
	CredentialKeyPrivateKeyPEMFile   = CredentialKeyPrivateKeyPEM + "_file"
	CredentialKeyPublicKeyPEM        = "public_key_pem" // inline public key PEM (ECDSA P-256/384/521 or Ed25519)
	CredentialKeyPublicKeyPEMFile    = CredentialKeyPublicKeyPEM + "_file"
	CredentialKeyOIDCToken           = "oidc_token"        // pre-obtained OIDC identity token for keyless signing
	CredentialKeyTrustedRootJSON     = "trusted_root_json" // inline trusted root JSON for offline verification
	CredentialKeyTrustedRootJSONFile = CredentialKeyTrustedRootJSON + "_file"
)

func PrivateKeyFromCredentials(credentials map[string]string) (crypto.PrivateKey, error) {
	b, err := loadBytes(credentials[CredentialKeyPrivateKeyPEM], CredentialKeyPrivateKeyPEMFile, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed loading private key PEM: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	return parsePrivateKeyPEM(b)
}

func PublicKeyFromCredentials(credentials map[string]string) (crypto.PublicKey, error) {
	b, err := loadBytes(credentials[CredentialKeyPublicKeyPEM], CredentialKeyPublicKeyPEMFile, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed loading public key PEM: %w", err)
	}
	if len(b) == 0 {
		pk, err := PrivateKeyFromCredentials(credentials)
		if err != nil {
			return nil, err
		}
		if pk == nil {
			return nil, nil
		}
		return publicKeyOf(pk)
	}
	pubKey, err := parsePublicKeyPEM(b)
	if err != nil {
		return nil, err
	}
	pk, err := PrivateKeyFromCredentials(credentials)
	if err != nil {
		return nil, err
	}
	if pk != nil {
		expectedPub, err := publicKeyOf(pk)
		if err != nil {
			return nil, err
		}
		if !expectedPub.(interface{ Equal(x crypto.PublicKey) bool }).Equal(pubKey) {
			return nil, fmt.Errorf("provided public key does not match the private key")
		}
	}
	return pubKey, nil
}

func OIDCTokenFromCredentials(credentials map[string]string) string {
	return credentials[CredentialKeyOIDCToken]
}

func TrustedRootFromCredentials(credentials map[string]string) ([]byte, error) {
	return loadBytes(credentials[CredentialKeyTrustedRootJSON], CredentialKeyTrustedRootJSONFile, credentials)
}

func loadBytes(val string, fileKey string, credentials map[string]string) ([]byte, error) {
	if val != "" {
		return []byte(val), nil
	}
	if path := credentials[fileKey]; path != "" {
		return os.ReadFile(path)
	}
	return nil, nil
}

// publicKeyOf extracts the public key from a private key.
func publicKeyOf(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	type publicker interface {
		Public() crypto.PublicKey
	}
	if p, ok := priv.(publicker); ok {
		return p.Public(), nil
	}
	return nil, fmt.Errorf("private key type %T does not expose a public key", priv)
}

// parsePrivateKeyPEM parses a PEM-encoded private key.
// Supported types: ECDSA (P-256, P-384, P-521) and Ed25519.
// PEM block types "EC PRIVATE KEY" (SEC 1) and "PRIVATE KEY" (PKCS8) are both accepted.
func parsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		if err := validateECDSACurve(key.Curve); err != nil {
			return nil, err
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		return validatePrivateKey(key)
	default:
		// Try SEC1 first, then PKCS8, to handle unlabelled or mislabelled blocks.
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			if err := validateECDSACurve(key.Curve); err != nil {
				return nil, err
			}
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return validatePrivateKey(key)
		}
		return nil, fmt.Errorf("unsupported PEM block type %q: expected EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}

// parsePublicKeyPEM parses a PEM-encoded PKIX public key.
// Supported types: ECDSA (P-256, P-384, P-521) and Ed25519.
func parsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return validatePublicKey(pub)
}

func validatePrivateKey(key interface{}) (crypto.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if err := validateECDSACurve(k.Curve); err != nil {
			return nil, err
		}
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T: only ECDSA (P-256, P-384, P-521) and Ed25519 are supported", key)
	}
}

func validatePublicKey(key interface{}) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if err := validateECDSACurve(k.Curve); err != nil {
			return nil, err
		}
		return k, nil
	case ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T: only ECDSA (P-256, P-384, P-521) and Ed25519 are supported", key)
	}
}

func validateECDSACurve(curve elliptic.Curve) error {
	name := curve.Params().Name
	switch name {
	case "P-256", "P-384", "P-521":
		return nil
	default:
		return fmt.Errorf("unsupported ECDSA curve %s: only P-256, P-384, and P-521 are supported", name)
	}
}

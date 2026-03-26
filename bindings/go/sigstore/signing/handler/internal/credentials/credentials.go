package credentials

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"ocm.software/open-component-model/bindings/go/runtime"
)

var IdentityTypeSigstore = runtime.NewVersionedType("Sigstore", "v1alpha1")

// Credential keys.
//
//nolint:gosec // these are not secrets
const (
	CredentialKeyPrivateKeyPEM       = "private_key_pem" // inline ECDSA private key PEM
	CredentialKeyPrivateKeyPEMFile   = CredentialKeyPrivateKeyPEM + "_file"
	CredentialKeyPublicKeyPEM        = "public_key_pem" // inline ECDSA public key PEM
	CredentialKeyPublicKeyPEMFile    = CredentialKeyPublicKeyPEM + "_file"
	CredentialKeyOIDCToken           = "oidc_token"        // pre-obtained OIDC identity token for keyless signing
	CredentialKeyTrustedRootJSON     = "trusted_root_json" // inline trusted root JSON for offline verification
	CredentialKeyTrustedRootJSONFile = CredentialKeyTrustedRootJSON + "_file"
)

func PrivateKeyFromCredentials(credentials map[string]string) (*ecdsa.PrivateKey, error) {
	b, err := loadBytes(credentials[CredentialKeyPrivateKeyPEM], CredentialKeyPrivateKeyPEMFile, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed loading private key PEM: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	return parseECDSAPrivateKeyPEM(b)
}

func PublicKeyFromCredentials(credentials map[string]string) (*ecdsa.PublicKey, error) {
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
		return &pk.PublicKey, nil
	}
	pubKey, err := parseECDSAPublicKeyPEM(b)
	if err != nil {
		return nil, err
	}
	pk, err := PrivateKeyFromCredentials(credentials)
	if err != nil {
		return nil, err
	}
	if pk != nil && !pk.PublicKey.Equal(pubKey) {
		return nil, fmt.Errorf("provided public key does not match the private key")
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

func parseECDSAPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// try PKCS8
		pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w (PKCS8: %w)", err, pkcs8Err)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not ECDSA, got %T", pkcs8Key)
		}
		return ecKey, nil
	}
	return key, nil
}

func parseECDSAPublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA, got %T", pub)
	}
	return ecKey, nil
}

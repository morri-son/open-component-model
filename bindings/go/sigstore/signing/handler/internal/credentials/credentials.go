package credentials

import (
	"os"

	"ocm.software/open-component-model/bindings/go/runtime"
)

var (
	IdentityTypeSign   = runtime.NewVersionedType("SigstoreSigningConfiguration", "v1alpha1")
	IdentityTypeVerify = runtime.NewVersionedType("SigstoreVerificationConfiguration", "v1alpha1")
)

// Credential keys.
const (
	CredentialKeyOIDCToken           = "token"             // pre-obtained OIDC identity token for keyless signing
	CredentialKeyTrustedRootJSON     = "trusted_root_json" // inline trusted root JSON for offline verification
	CredentialKeyTrustedRootJSONFile = CredentialKeyTrustedRootJSON + "_file"
)

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

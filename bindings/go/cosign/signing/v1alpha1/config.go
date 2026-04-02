package v1alpha1

import (
	"ocm.software/open-component-model/bindings/go/runtime"
)

const (
	SignConfigType   = "SigstoreSigningConfiguration"
	VerifyConfigType = "SigstoreVerificationConfiguration"
)

var Scheme = runtime.NewScheme()

func init() {
	Scheme.MustRegisterWithAlias(&SignConfig{},
		runtime.NewUnversionedType(SignConfigType),
		runtime.NewVersionedType(SignConfigType, Version),
	)
	Scheme.MustRegisterWithAlias(&VerifyConfig{},
		runtime.NewUnversionedType(VerifyConfigType),
		runtime.NewVersionedType(VerifyConfigType, Version),
	)
}

// SignConfig defines configuration for Sigstore-based keyless signing via the cosign CLI.
//
// When no endpoint URLs are configured, cosign uses the public-good Sigstore infrastructure
// by default. When an OIDC token is available in credentials, it is passed via
// --identity-token; otherwise cosign opens a browser for interactive OIDC authentication.
//
// +k8s:deepcopy-gen:interfaces=ocm.software/open-component-model/bindings/go/runtime.Typed
// +k8s:deepcopy-gen=true
type SignConfig struct {
	// Type identifies this configuration object's runtime type.
	Type runtime.Type `json:"type"`

	// FulcioURL is the URL of the Fulcio certificate authority for keyless signing.
	FulcioURL string `json:"fulcioURL,omitempty"`

	// RekorURL is the URL of the Rekor transparency log.
	RekorURL string `json:"rekorURL,omitempty"`

	// TSAURL is the full URL of a RFC 3161 Timestamp Authority endpoint.
	TSAURL string `json:"tsaURL,omitempty"`
}

// VerifyConfig defines configuration for Sigstore-based keyless verification via the cosign CLI.
//
// Verification requires at least one identity field (ExpectedIssuer, ExpectedSAN,
// or their regex variants). The cosign CLI validates the Fulcio certificate against the
// trusted root and identity constraints.
//
// +k8s:deepcopy-gen:interfaces=ocm.software/open-component-model/bindings/go/runtime.Typed
// +k8s:deepcopy-gen=true
type VerifyConfig struct {
	// Type identifies this configuration object's runtime type.
	Type runtime.Type `json:"type"`

	// TrustedRootPath is a filesystem path to a trusted root JSON file for offline verification.
	TrustedRootPath string `json:"trustedRootPath,omitempty"`

	// ExpectedIssuer is the exact OIDC issuer URL to verify against.
	ExpectedIssuer string `json:"expectedIssuer,omitempty"`

	// ExpectedIssuerRegex is a regular expression to match the OIDC issuer.
	ExpectedIssuerRegex string `json:"expectedIssuerRegex,omitempty"`

	// ExpectedSAN is the exact Subject Alternative Name to verify against.
	ExpectedSAN string `json:"expectedSAN,omitempty"`

	// ExpectedSANRegex is a regular expression to match the Subject Alternative Name.
	ExpectedSANRegex string `json:"expectedSANRegex,omitempty"`
}

// GetType implements runtime.Typed.
func (c *SignConfig) GetType() runtime.Type { return c.Type }

// SetType implements runtime.Typed.
func (c *SignConfig) SetType(t runtime.Type) { c.Type = t }

// DeepCopyTyped implements runtime.Typed.
func (c *SignConfig) DeepCopyTyped() runtime.Typed {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

// GetType implements runtime.Typed.
func (c *VerifyConfig) GetType() runtime.Type { return c.Type }

// SetType implements runtime.Typed.
func (c *VerifyConfig) SetType(t runtime.Type) { c.Type = t }

// DeepCopyTyped implements runtime.Typed.
func (c *VerifyConfig) DeepCopyTyped() runtime.Typed {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

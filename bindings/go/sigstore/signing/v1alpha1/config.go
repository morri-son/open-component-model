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

// SignConfig defines configuration for Sigstore-based signing.
//
// # Endpoint Discovery
//
// When no endpoint URLs (FulcioURL, RekorURL, TSAURL) or SigningConfigPath
// are configured, the library automatically fetches the public-good Sigstore signing
// configuration from the Sigstore TUF repository. This enables
// zero-configuration signing against the public Sigstore infrastructure.
// This matches the default behavior of Cosign v3 (https://blog.sigstore.dev/cosign-3-0-available/).
//
// To use explicit endpoints instead, set the individual URL fields or provide a
// SigningConfigPath.
//
// # Signing Modes
//
// Keyless: an OIDC token (from credentials or a credential plugin) produces a
// short-lived Fulcio certificate embedded in the bundle along with the signer's identity.
//
// Key-based: a private key from credentials signs the artifact. The bundle stores only a
// public key hint (an opaque identifier), not the actual public key material. This follows
// the Sigstore bundle specification: "Like traditional PKI key distribution the format of
// the hint must be agreed upon out of band by the signer and the verifiers. The key itself
// is not embedded in the Sigstore bundle." (https://docs.sigstore.dev/about/bundle)
//
// +k8s:deepcopy-gen:interfaces=ocm.software/open-component-model/bindings/go/runtime.Typed
// +k8s:deepcopy-gen=true
// +ocm:typegen=true
// +ocm:jsonschema-gen=true
type SignConfig struct {
	// Type identifies this configuration object's runtime type.
	// +ocm:jsonschema-gen:enum=SigstoreSigningConfiguration/v1alpha1
	// +ocm:jsonschema-gen:enum:deprecated=SigstoreSigningConfiguration
	Type runtime.Type `json:"type"`

	// FulcioURL is the URL of the Fulcio certificate authority for keyless signing.
	// Required when an OIDC token is available and SigningConfigPath is not set.
	FulcioURL string `json:"fulcioURL,omitempty"`

	// RekorURL is the URL of the Rekor transparency log.
	// When empty and SigningConfigPath is not set, no transparency log entry is created.
	RekorURL string `json:"rekorURL,omitempty"`

	// TSAURL is the full URL of a RFC 3161 Timestamp Authority endpoint
	// (e.g. "https://timestamp.sigstore.dev/api/v1/timestamp").
	// When set, a TSA timestamp is obtained at sign time.
	// Rekor v2 keyless flows require a TSA because v2 does not produce signed entry timestamps.
	TSAURL string `json:"tsaURL,omitempty"`

	// SigningConfigPath is a filesystem path to a signing_config.json file.
	// When set, service endpoints (Fulcio, Rekor, TSA) are discovered from this file
	// instead of using the individual URL fields. This is the standard Sigstore mechanism
	// for service endpoint discovery and supports automatic Rekor v2 selection.
	SigningConfigPath string `json:"signingConfigPath,omitempty"`

	// RekorVersion specifies the Rekor API version to use (1 or 2).
	// When 0 (default), version 1 is used for direct URL mode.
	// When a SigningConfigPath is provided, the highest available version is auto-selected.
	RekorVersion uint32 `json:"rekorVersion,omitempty"`

	// SkipRekor disables transparency log integration during signing.
	// When true, signatures are not uploaded to Rekor.
	SkipRekor bool `json:"skipRekor,omitempty"`
}

// VerifyConfig defines configuration for Sigstore-based verification.
//
// # Trusted Root Discovery
//
// Trusted root material is resolved from credentials, TrustedRootPath,
// TUFRootURL, or (as a fallback) the public-good Sigstore TUF repository.
//
// # Verification Modes
//
// Keyless verification requires at least one identity field (ExpectedIssuer, ExpectedSAN,
// or their regex variants). The Fulcio certificate in the bundle is validated against the
// trusted root's CA key and the identity constraints. No external key material is needed.
//
// Key-based verification requires the public key to be provided out of band via credentials,
// since the bundle only contains a hint. Without the public key, verification fails.
//
// +k8s:deepcopy-gen:interfaces=ocm.software/open-component-model/bindings/go/runtime.Typed
// +k8s:deepcopy-gen=true
// +ocm:typegen=true
// +ocm:jsonschema-gen=true
type VerifyConfig struct {
	// Type identifies this configuration object's runtime type.
	// +ocm:jsonschema-gen:enum=SigstoreVerificationConfiguration/v1alpha1
	// +ocm:jsonschema-gen:enum:deprecated=SigstoreVerificationConfiguration
	Type runtime.Type `json:"type"`

	// TUFRootURL is the URL of a TUF repository for fetching trusted root material.
	// When empty, TUF is not used; provide a trusted root via credentials or TrustedRootPath instead.
	// When set, TUFInitialRoot must also be provided as the trust anchor.
	TUFRootURL string `json:"tufRootURL,omitempty"`

	// TUFInitialRoot is the initial (pinned) TUF root.json used to bootstrap trust
	// when fetching from a custom TUF mirror (TUFRootURL). This is mandatory when
	// TUFRootURL is set — the TUF security model requires a known-good initial root
	// to verify all subsequent metadata. The value is raw JSON (not base64-encoded).
	TUFInitialRoot string `json:"tufInitialRoot,omitempty"`

	// TrustedRootPath is a filesystem path to a trusted root JSON file for offline verification.
	// When set, this takes precedence over TUF-based root fetching.
	TrustedRootPath string `json:"trustedRootPath,omitempty"`

	// ExpectedIssuer is the exact OIDC issuer URL to verify against in keyless signatures.
	// Used during verification to match the Fulcio certificate's issuer extension.
	ExpectedIssuer string `json:"expectedIssuer,omitempty"`

	// ExpectedIssuerRegex is a regular expression to match the OIDC issuer in keyless signatures.
	// Mutually exclusive with ExpectedIssuer — if both are set, ExpectedIssuer takes precedence.
	ExpectedIssuerRegex string `json:"expectedIssuerRegex,omitempty"`

	// ExpectedSAN is the exact Subject Alternative Name to verify against in keyless signatures.
	// This is the identity (email or URI) embedded in the Fulcio certificate.
	ExpectedSAN string `json:"expectedSAN,omitempty"`

	// ExpectedSANRegex is a regular expression to match the Subject Alternative Name.
	// Mutually exclusive with ExpectedSAN — if both are set, ExpectedSAN takes precedence.
	ExpectedSANRegex string `json:"expectedSANRegex,omitempty"`

	// SkipRekor disables transparency log verification.
	// When true, Rekor entries are not required for verification.
	SkipRekor bool `json:"skipRekor,omitempty"`
}

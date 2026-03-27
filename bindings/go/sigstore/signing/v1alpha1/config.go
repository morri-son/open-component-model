package v1alpha1

import (
	"ocm.software/open-component-model/bindings/go/runtime"
)

const ConfigType = "SigstoreSigningConfiguration"

var Scheme = runtime.NewScheme()

func init() {
	Scheme.MustRegisterWithAlias(&Config{},
		runtime.NewUnversionedType(ConfigType),
		runtime.NewVersionedType(ConfigType, Version),
	)
}

// Config defines configuration for Sigstore-based signing and verification.
//
// The library does not provide default endpoint URLs. All URLs must be explicitly
// configured, either individually (FulcioURL, RekorURL, TSAURL) or via a
// SigningConfigPath. CLI layers should set appropriate defaults for user convenience.
//
// For keyless verification, at least one identity field (ExpectedIssuer, ExpectedSAN,
// or their regex variants) must be set. If no identity fields and no public key
// credential are provided, verification returns an error.
//
// +k8s:deepcopy-gen:interfaces=ocm.software/open-component-model/bindings/go/runtime.Typed
// +k8s:deepcopy-gen=true
// +ocm:typegen=true
// +ocm:jsonschema-gen=true
type Config struct {
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
	// When empty, no timestamp authority is used unless ForceTSA is set.
	TSAURL string `json:"tsaURL,omitempty"`

	// TUFRootURL is the URL of a TUF repository for fetching trusted root material.
	// When empty, TUF is not used; provide a trusted root via credentials or TrustedRootPath instead.
	TUFRootURL string `json:"tufRootURL,omitempty"`

	// TrustedRootPath is a filesystem path to a trusted root JSON file for offline verification.
	// When set, this takes precedence over TUF-based root fetching.
	TrustedRootPath string `json:"trustedRootPath,omitempty"`

	// SigningConfigPath is a filesystem path to a signing_config.json file.
	// When set, service endpoints (Fulcio, Rekor, TSA) are discovered from this file
	// instead of using the individual URL fields. This is the standard Sigstore mechanism
	// for service endpoint discovery and supports automatic Rekor v2 selection.
	SigningConfigPath string `json:"signingConfigPath,omitempty"`

	// RekorVersion specifies the Rekor API version to use (1 or 2).
	// When 0 (default), version 1 is used for direct URL mode.
	// When a SigningConfigPath is provided, the highest available version is auto-selected.
	RekorVersion uint32 `json:"rekorVersion,omitempty"`

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

	// SkipRekor disables transparency log integration.
	// When true, signatures are not uploaded to Rekor and Rekor entries are not required for verification.
	SkipRekor bool `json:"skipRekor,omitempty"`

	// ForceTSA forces the use of a Timestamp Authority even when Rekor is available.
	// By default, Rekor's integrated timestamps are used. When set, a TSA timestamp is also obtained.
	ForceTSA bool `json:"forceTSA,omitempty"`
}

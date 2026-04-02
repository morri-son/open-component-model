package sigstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"ocm.software/open-component-model/bindings/go/credentials"
	"ocm.software/open-component-model/bindings/go/runtime"
)

const (
	// OIDCPluginType is the credential type for the SigstoreOIDC credential plugin.
	// It is used in .ocmconfig to trigger interactive OIDC token acquisition.
	OIDCPluginType = "SigstoreOIDC"

	// OIDCPluginVersion is the version of the SigstoreOIDC credential plugin type.
	OIDCPluginVersion = "v1alpha1"

	// configKeyIssuer is the JSON key for the OIDC issuer URL in the plugin credential config.
	configKeyIssuer = "issuer"

	// configKeyClientID is the JSON key for the OIDC client ID in the plugin credential config.
	configKeyClientID = "clientID"

	// credentialKeyOIDCToken is the credential key for the resolved OIDC token.
	// Must match v1alpha1.CredentialKeyToken and the constant in
	// sigstore/signing/handler/internal/credentials.
	credentialKeyOIDCToken = "token"

	// defaultOIDCIssuer is the public-good Sigstore OIDC issuer.
	defaultOIDCIssuer = "https://oauth2.sigstore.dev/auth"

	// defaultOIDCClientID is the public-good Sigstore OIDC client ID.
	defaultOIDCClientID = "sigstore"
)

// OIDCPluginTypeVersioned is the fully qualified versioned type for the SigstoreOIDC credential plugin.
var OIDCPluginTypeVersioned = runtime.NewVersionedType(OIDCPluginType, OIDCPluginVersion)

// OIDCPlugin implements the credentials.CredentialPlugin interface for
// interactive OIDC token acquisition. It is used in the credential graph
// to resolve OIDC identity tokens for keyless Sigstore signing.
//
// When a consumer in .ocmconfig has a credential of type SigstoreOIDC/v1alpha1,
// the credential graph uses this plugin to:
//  1. Map the credential to a consumer identity (during graph ingestion).
//  2. Acquire an OIDC token at resolution time (via environment variable
//     or interactive browser flow).
//
// Example .ocmconfig entry:
//
//	consumers:
//	- identity:
//	    type: SigstoreSigningConfiguration/v1alpha1
//	    algorithm: sigstore
//	    signature: default
//	  credentials:
//	  - type: SigstoreOIDC/v1alpha1
//	    issuer: https://oauth2.sigstore.dev/auth
//	    clientID: sigstore
type OIDCPlugin struct{}

var _ credentials.CredentialPlugin = (*OIDCPlugin)(nil)

// GetConsumerIdentity maps a SigstoreOIDC credential to a consumer identity
// for the credential graph. The returned identity has the same type as the
// credential (SigstoreOIDC/v1alpha1) and carries the issuer as an attribute.
func (p *OIDCPlugin) GetConsumerIdentity(_ context.Context, credential runtime.Typed) (runtime.Identity, error) {
	cfg, err := parseOIDCConfig(credential)
	if err != nil {
		return nil, err
	}

	id := runtime.Identity{
		configKeyIssuer: cfg.issuer,
	}
	id.SetType(OIDCPluginTypeVersioned)
	return id, nil
}

// Resolve acquires an OIDC identity token. It checks the SIGSTORE_ID_TOKEN
// environment variable first (for CI/non-interactive use), then falls back
// to an interactive browser-based OIDC flow.
func (p *OIDCPlugin) Resolve(_ context.Context, identity runtime.Identity, _ map[string]string) (map[string]string, error) {
	if tok := os.Getenv("SIGSTORE_ID_TOKEN"); tok != "" {
		return map[string]string{
			credentialKeyOIDCToken: tok,
		}, nil
	}

	issuer := identity[configKeyIssuer]
	if issuer == "" {
		issuer = defaultOIDCIssuer
	}
	clientID := identity[configKeyClientID]
	if clientID == "" {
		clientID = defaultOIDCClientID
	}

	result, err := oauthflow.OIDConnect(issuer, clientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return nil, fmt.Errorf("interactive OIDC authentication: %w", err)
	}

	return map[string]string{
		credentialKeyOIDCToken: result.RawString,
	}, nil
}

// oidcConfig holds the parsed SigstoreOIDC credential configuration.
type oidcConfig struct {
	issuer   string
	clientID string
}

// parseOIDCConfig extracts issuer and clientID from a SigstoreOIDC credential.
// Both fields are optional; defaults are applied at resolution time.
func parseOIDCConfig(typed runtime.Typed) (*oidcConfig, error) {
	data, err := json.Marshal(typed)
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal credential: %w", err)
	}

	cfg := &oidcConfig{
		issuer:   defaultOIDCIssuer,
		clientID: defaultOIDCClientID,
	}
	if v, ok := raw[configKeyIssuer].(string); ok && v != "" {
		cfg.issuer = v
	}
	if v, ok := raw[configKeyClientID].(string); ok && v != "" {
		cfg.clientID = v
	}
	return cfg, nil
}

package v1alpha1

import (
	"ocm.software/open-component-model/bindings/go/runtime"
)

const (
	// OIDCIdentityTokenType is the type name for OIDC identity token credentials.
	OIDCIdentityTokenType = "OIDCIdentityToken"

	// CredentialKeyToken is the credential map key for the OIDC identity token.
	// Used in the current map[string]string credential flow; will be superseded
	// once the credential graph operates on runtime.Typed directly.
	CredentialKeyToken = "token"
)

// OIDCIdentityToken represents a resolved OIDC identity token credential
// for keyless Sigstore signing. It carries a single bearer token obtained
// from an OIDC provider (e.g. the public-good Sigstore Dex instance).
//
// This type is defined now so the credential graph team can reference it
// when implementing typed credential resolution. Until then, the signing
// handler reads the token from the map[string]string credential flow
// using CredentialKeyToken.
//
// +k8s:deepcopy-gen:interfaces=ocm.software/open-component-model/bindings/go/runtime.Typed
// +k8s:deepcopy-gen=true
// +ocm:typegen=true
type OIDCIdentityToken struct {
	Type  runtime.Type `json:"type"`
	Token string       `json:"token"`
}

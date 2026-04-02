// Package cosign provides a signing handler for the Open Component Model
// that implements Sigstore-based keyless signing and verification by delegating
// to the cosign CLI tool.
//
// This handler invokes cosign as an external process, keeping the transitive
// dependency footprint minimal while producing standard Sigstore protobuf
// bundles (v0.3).
//
// OIDC token acquisition for keyless signing is handled by cosign directly.
// When a token is available in credentials (e.g. via the SIGSTORE_ID_TOKEN
// environment variable or a manual .ocmconfig entry), it is passed to cosign
// via --identity-token. When no token is available, cosign opens a browser
// for interactive OIDC authentication (via --fulcio-auth-flow=normal).
//
// The handler registers under the type names SigstoreSigningConfiguration/v1alpha1
// and SigstoreVerificationConfiguration/v1alpha1, matching the standard Sigstore
// signing types in the OCM ecosystem.
package cosign

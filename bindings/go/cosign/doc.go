// Package cosign provides a signing handler for the Open Component Model
// that implements Sigstore-based keyless signing and verification by delegating
// to the cosign CLI tool.
//
// Unlike the sigstore handler (which embeds sigstore-go as a library dependency),
// this handler invokes cosign as an external process, dramatically reducing the
// transitive dependency footprint while producing identical Sigstore protobuf
// bundles (v0.3).
//
// OIDC token acquisition is delegated to cosign: when no identity token is
// provided via credentials, cosign opens a browser for interactive authentication.
// When a token is available (e.g. from the SIGSTORE_ID_TOKEN environment variable
// or the OCM credential graph), it is passed via --identity-token.
//
// This is a proof-of-concept implementation to evaluate the feasibility of
// replacing the sigstore-go library dependency with cosign CLI invocations.
package cosign

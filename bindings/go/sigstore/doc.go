// Package sigstore provides a signing handler for the Open Component Model
// that implements Sigstore-based keyless signing and verification using the
// sigstore-go library.
//
// It produces standard Sigstore protobuf bundles (v0.3) using keyless signing
// with Fulcio and OIDC identity tokens.
//
// With no explicit configuration, the handler automatically discovers service endpoints
// and trust material from the public-good Sigstore TUF repository, matching the default
// behavior of Cosign v3 (https://blog.sigstore.dev/cosign-3-0-available/).
//
// Bundles embed the full Fulcio certificate (including the signer's identity),
// so verification needs only a trusted root and identity constraints — no key distribution.
package sigstore

// Package sigstore provides a signing handler for the Open Component Model
// that implements Sigstore-based signing and verification using the sigstore-go library.
//
// It produces standard Sigstore protobuf bundles (v0.3) and supports both keyless
// (Fulcio + OIDC) and key-based (ECDSA/Ed25519) signing modes.
//
// With no explicit configuration, the handler automatically discovers service endpoints
// and trust material from the public-good Sigstore TUF repository, matching the default
// behavior of Cosign v3 (https://blog.sigstore.dev/cosign-3-0-available/).
//
// The two signing modes differ in what the bundle contains for verification:
//
//   - Keyless bundles embed the full Fulcio certificate (including the signer's identity),
//     so verification needs only a trusted root and identity constraints — no key distribution.
//
//   - Key-based bundles store only a public key hint (an opaque identifier, not the key itself).
//     The verifier must receive the public key out of band, for example via OCM credentials.
//     This is standard Sigstore behavior per the bundle specification.
package sigstore

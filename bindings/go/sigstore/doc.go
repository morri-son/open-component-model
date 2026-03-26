// Package sigstore provides a signing handler for the Open Component Model
// that implements Sigstore-based signing and verification using the sigstore-go library.
//
// It produces standard Sigstore protobuf bundles (v0.3) and supports both keyless
// (Fulcio + OIDC) and key-based (ECDSA) signing modes.
package sigstore

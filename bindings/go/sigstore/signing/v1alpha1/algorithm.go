package v1alpha1

const (
	// AlgorithmSigstore is the identifier for the Sigstore signing algorithm.
	//
	// Sigstore provides keyless signing via Fulcio (short-lived certificates bound to OIDC identities)
	// and transparency via Rekor (an append-only transparency log). It also supports key-based
	// signing with ECDSA keys.
	//
	// The signature value contains a standard Sigstore protobuf bundle that includes all
	// verification material (certificate chain, transparency log entries, timestamps).
	//
	// References:
	//   - Sigstore specification: https://docs.sigstore.dev/
	//   - Protobuf bundle format: https://github.com/sigstore/protobuf-specs
	AlgorithmSigstore = "sigstore"

	// MediaTypeSigstoreBundle is the media type for a Sigstore protobuf bundle encoded as JSON.
	// The bundle is self-contained and includes all verification material needed for offline verification.
	MediaTypeSigstoreBundle = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

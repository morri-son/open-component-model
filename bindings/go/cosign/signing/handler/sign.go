package handler

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"ocm.software/open-component-model/bindings/go/cosign/signing/v1alpha1"
	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
)

func doSign(
	ctx context.Context,
	unsigned descruntime.Digest,
	cfg *v1alpha1.SignConfig,
	creds map[string]string,
	executor Executor,
) (descruntime.SignatureInfo, error) {
	token := creds[CredentialKeyOIDCToken]
	if token == "" {
		return descruntime.SignatureInfo{}, fmt.Errorf("OIDC identity token required for signing: " +
			"configure a SigstoreOIDC/v1alpha1 credential in .ocmconfig " +
			"or set the SIGSTORE_ID_TOKEN environment variable")
	}

	digestBytes, err := hex.DecodeString(unsigned.Value)
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("decode digest hex value: %w", err)
	}

	dataFile, err := os.CreateTemp("", "cosign-sign-data-*")
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("create temp data file: %w", err)
	}
	defer os.Remove(dataFile.Name())

	if _, err := dataFile.Write(digestBytes); err != nil {
		dataFile.Close()
		return descruntime.SignatureInfo{}, fmt.Errorf("write digest to temp file: %w", err)
	}
	dataFile.Close()

	bundleFile, err := os.CreateTemp("", "cosign-sign-bundle-*.json")
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("create temp bundle file: %w", err)
	}
	bundleFile.Close()
	defer os.Remove(bundleFile.Name())

	opts := SignOpts{
		BundleOutPath: bundleFile.Name(),
		IdentityToken: token,
		FulcioURL:     cfg.FulcioURL,
		RekorURL:      cfg.RekorURL,
		TSAURL:        cfg.TSAURL,
	}

	bundleJSON, err := executor.SignBlob(ctx, dataFile.Name(), opts)
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("cosign sign: %w", err)
	}

	issuer := extractIssuerFromBundleJSON(bundleJSON)

	return descruntime.SignatureInfo{
		Algorithm: v1alpha1.AlgorithmSigstore,
		MediaType: v1alpha1.MediaTypeSigstoreBundle,
		Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		Issuer:    issuer,
	}, nil
}

// sigstoreIssuerV1OID is the Fulcio OIDC issuer extension (v1, deprecated).
// OID 1.3.6.1.4.1.57264.1.1 — raw UTF-8 string.
var sigstoreIssuerV1OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

// sigstoreIssuerV2OID is the Fulcio OIDC issuer extension (v2).
// OID 1.3.6.1.4.1.57264.1.8 — ASN.1 UTF8String.
var sigstoreIssuerV2OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// extractIssuerFromBundleJSON parses a Sigstore bundle JSON to extract the OIDC
// issuer from the Fulcio certificate, using only standard library types.
func extractIssuerFromBundleJSON(bundleJSON []byte) string {
	var bundle struct {
		VerificationMaterial struct {
			Certificate struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return ""
	}

	certDER, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.Certificate.RawBytes)
	if err != nil || len(certDER) == 0 {
		return ""
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ""
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sigstoreIssuerV2OID) {
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil {
				return issuer
			}
		}
		if ext.Id.Equal(sigstoreIssuerV1OID) {
			return string(ext.Value)
		}
	}

	return ""
}

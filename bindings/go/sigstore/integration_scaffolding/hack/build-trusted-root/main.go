// build-trusted-root builds a Sigstore trusted_root.json from raw PEM material
// extracted from a sigstore/scaffolding Kubernetes cluster.
//
// Unlike "cosign trusted-root create", this tool produces a trusted root that
// is compatible with cosign's --trusted-root flag for both signing and
// verification. The key differences:
//
//  1. logId.keyId is the SHA-256 of the DER-encoded SubjectPublicKeyInfo,
//     which is the standard Sigstore v1 tlog log ID format.
//  2. publicKey.keyDetails is derived from the actual key type (ECDSA, Ed25519,
//     RSA) rather than a fixed default.
//  3. The certificate chain format matches what cosign expects.
//
// Usage:
//
//	go run ./hack/build-trusted-root \
//	  --fulcio-cert=fulcio-root.pem \
//	  --rekor-key=rekor.pub \
//	  --rekor-url=http://rekor.rekor-system.svc \
//	  --ctlog-key=ctlog.pub \
//	  --ctlog-url=http://ctlog.ctlog-system.svc \
//	  --tsa-chain=tsa-chain.pem \
//	  --tsa-url=http://tsa.tsa-system.svc/api/v1/timestamp \
//	  --fulcio-url=http://fulcio.fulcio-system.svc \
//	  --out=trusted_root.json
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	var (
		fulcioCert string
		rekorKey   string
		rekorURL   string
		ctlogKey   string
		ctlogURL   string
		tsaChain   string
		tsaURL     string
		fulcioURL  string
		outPath    string
	)

	flag.StringVar(&fulcioCert, "fulcio-cert", "", "Path to Fulcio root CA certificate PEM")
	flag.StringVar(&rekorKey, "rekor-key", "", "Path to Rekor public key PEM")
	flag.StringVar(&rekorURL, "rekor-url", "", "Rekor base URL")
	flag.StringVar(&ctlogKey, "ctlog-key", "", "Path to CT log public key PEM (optional)")
	flag.StringVar(&ctlogURL, "ctlog-url", "", "CT log base URL (optional)")
	flag.StringVar(&tsaChain, "tsa-chain", "", "Path to TSA certificate chain PEM (optional)")
	flag.StringVar(&tsaURL, "tsa-url", "", "TSA URL (optional)")
	flag.StringVar(&fulcioURL, "fulcio-url", "", "Fulcio URL")
	flag.StringVar(&outPath, "out", "trusted_root.json", "Output path for trusted_root.json")
	flag.Parse()

	if fulcioCert == "" || rekorKey == "" || rekorURL == "" || fulcioURL == "" {
		log.Fatal("--fulcio-cert, --rekor-key, --rekor-url, and --fulcio-url are required")
	}

	fulcioCertPEM, err := os.ReadFile(fulcioCert)
	if err != nil {
		log.Fatalf("read fulcio cert: %v", err)
	}

	rekorKeyPEM, err := os.ReadFile(rekorKey)
	if err != nil {
		log.Fatalf("read rekor key: %v", err)
	}

	trustedRoot, err := buildTrustedRoot(buildParams{
		fulcioCertPEM: fulcioCertPEM,
		rekorKeyPEM:   rekorKeyPEM,
		rekorURL:      rekorURL,
		fulcioURL:     fulcioURL,
		ctlogKeyPath:  ctlogKey,
		ctlogURL:      ctlogURL,
		tsaChainPath:  tsaChain,
		tsaURL:        tsaURL,
	})
	if err != nil {
		log.Fatalf("build trusted root: %v", err)
	}

	data, err := json.MarshalIndent(trustedRoot, "", "  ")
	if err != nil {
		log.Fatalf("marshal JSON: %v", err)
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		log.Fatalf("write output: %v", err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
}

type buildParams struct {
	fulcioCertPEM []byte
	rekorKeyPEM   []byte
	rekorURL      string
	fulcioURL     string
	ctlogKeyPath  string
	ctlogURL      string
	tsaChainPath  string
	tsaURL        string
}

func buildTrustedRoot(p buildParams) (map[string]any, error) {
	fulcioCertDER, err := pemToDER(p.fulcioCertPEM, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("decode fulcio cert: %w", err)
	}

	rekorKeyDER, err := pemToPublicKeyDER(p.rekorKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decode rekor key: %w", err)
	}

	keyDetails, err := publicKeyDetails(p.rekorKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("rekor key details: %w", err)
	}

	// Compute the Sigstore v1 tlog log ID: the SHA-256 of the
	// DER-encoded SubjectPublicKeyInfo of the transparency log's public key.
	logID := sha256.Sum256(rekorKeyDER)

	now := time.Now().UTC().Format(time.RFC3339)

	root := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"certificateAuthorities": []map[string]any{
			{
				"subject": map[string]any{
					"organization": "sigstore",
					"commonName":   "fulcio",
				},
				"uri": p.fulcioURL,
				"certChain": map[string]any{
					"certificates": []map[string]any{
						{
							"rawBytes": base64.StdEncoding.EncodeToString(fulcioCertDER),
						},
					},
				},
				"validFor": map[string]any{
					"start": now,
				},
			},
		},
		"tlogs": []map[string]any{
			{
				"baseUrl":       p.rekorURL,
				"hashAlgorithm": "SHA2_256",
				"publicKey": map[string]any{
					"rawBytes":   base64.StdEncoding.EncodeToString(rekorKeyDER),
					"keyDetails": keyDetails,
					"validFor": map[string]any{
						"start": now,
					},
				},
				"logId": map[string]any{
					"keyId": base64.StdEncoding.EncodeToString(logID[:]),
				},
			},
		},
	}

	ctlogs, err := buildCTLogEntries(p, now)
	if err != nil {
		return nil, fmt.Errorf("build ctlog entries: %w", err)
	}
	root["ctlogs"] = ctlogs

	tsaEntries, err := buildTSAEntries(p, now)
	if err != nil {
		return nil, fmt.Errorf("build TSA entries: %w", err)
	}
	root["timestampAuthorities"] = tsaEntries

	return root, nil
}

func buildCTLogEntries(p buildParams, now string) ([]any, error) {
	if p.ctlogKeyPath == "" {
		return []any{}, nil
	}

	keyPEM, err := os.ReadFile(p.ctlogKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read ctlog key %s: %w", p.ctlogKeyPath, err)
	}

	keyDER, err := pemToPublicKeyDER(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("decode ctlog key: %w", err)
	}

	details, err := publicKeyDetails(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ctlog key details: %w", err)
	}

	logID := sha256.Sum256(keyDER)

	return []any{
		map[string]any{
			"baseUrl":       p.ctlogURL,
			"hashAlgorithm": "SHA2_256",
			"publicKey": map[string]any{
				"rawBytes":   base64.StdEncoding.EncodeToString(keyDER),
				"keyDetails": details,
				"validFor": map[string]any{
					"start": now,
				},
			},
			"logId": map[string]any{
				"keyId": base64.StdEncoding.EncodeToString(logID[:]),
			},
		},
	}, nil
}

func buildTSAEntries(p buildParams, now string) ([]any, error) {
	if p.tsaChainPath == "" {
		return []any{}, nil
	}

	chainPEM, err := os.ReadFile(p.tsaChainPath)
	if err != nil {
		return nil, fmt.Errorf("read TSA chain %s: %w", p.tsaChainPath, err)
	}

	certs, err := parsePEMCertificates(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TSA certificates: %w", err)
	}

	certEntries := make([]map[string]any, 0, len(certs))
	for _, certDER := range certs {
		certEntries = append(certEntries, map[string]any{
			"rawBytes": base64.StdEncoding.EncodeToString(certDER),
		})
	}

	return []any{
		map[string]any{
			"subject": map[string]any{
				"organization": "sigstore",
				"commonName":   "tsa",
			},
			"uri": p.tsaURL,
			"certChain": map[string]any{
				"certificates": certEntries,
			},
			"validFor": map[string]any{
				"start": now,
			},
		},
	}, nil
}

// pemToDER decodes a single PEM block of the expected type.
func pemToDER(pemData []byte, expectedType string) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block of type %s", expectedType)
	}
	if block.Type != expectedType {
		return nil, fmt.Errorf("expected PEM type %s, got %s", expectedType, block.Type)
	}
	return block.Bytes, nil
}

// pemToPublicKeyDER decodes a PEM public key to its DER-encoded SubjectPublicKeyInfo form.
func pemToPublicKeyDER(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// publicKeyDetails returns the Sigstore keyDetails enum string for a PEM public key.
func publicKeyDetails(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "PKIX_ECDSA_P256_SHA_256", nil
		case elliptic.P384():
			return "PKIX_ECDSA_P384_SHA_384", nil
		case elliptic.P521():
			return "PKIX_ECDSA_P521_SHA_512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		return "PKIX_ED25519", nil
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return "PKIX_RSA_PKCS1V15_2048_SHA256", nil
		case 3072:
			return "PKIX_RSA_PKCS1V15_3072_SHA256", nil
		case 4096:
			return "PKIX_RSA_PKCS1V15_4096_SHA256", nil
		default:
			return "", fmt.Errorf("unsupported RSA key size: %d", k.N.BitLen())
		}
	default:
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}

// parsePEMCertificates extracts DER-encoded certificates from a PEM bundle.
func parsePEMCertificates(pemData []byte) ([][]byte, error) {
	var certs [][]byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in PEM data (%d bytes)", len(pemData))
	}
	return certs, nil
}

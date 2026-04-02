# Cosign Integration Tests

Integration tests for the OCM cosign signing/verification handler.
Tests cover keyless (Fulcio + OIDC) signing and verification via the `cosign` CLI tool.

## Prerequisites

- [cosign](https://github.com/sigstore/cosign?tab=readme-ov-file#installation)
- [kind](https://kind.sigs.k8s.io/) (for local Sigstore stack)
- kubectl, Helm, curl, jq

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SIGSTORE_OIDC_TOKEN` | Yes | OIDC identity token for keyless signing |
| `SIGSTORE_FULCIO_URL` | No | Fulcio CA URL (default: public-good) |
| `SIGSTORE_REKOR_URL` | No | Rekor v1 URL (default: public-good) |
| `SIGSTORE_TSA_URL` | No | RFC 3161 Timestamp Authority URL |
| `SIGSTORE_TRUSTED_ROOT_PATH` | Yes | Path to trusted_root.json |
| `SIGSTORE_REKOR_V2_URL` | No | Rekor v2 URL (enables v2 tests) |
| `SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH` | No | Trusted root for Rekor v2 |

## Running

```bash
task bindings/go/cosign/integration:test
```

Tests skip gracefully when required environment variables are not set.

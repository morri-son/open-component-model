package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// defaultOperationTimeout is the maximum duration for a single cosign invocation
// when the caller's context has no deadline.
const defaultOperationTimeout = 3 * time.Minute

// Executor abstracts cosign CLI invocations for testability.
type Executor interface {
	SignBlob(ctx context.Context, dataPath string, opts SignOpts) (bundleJSON []byte, err error)
	VerifyBlob(ctx context.Context, dataPath, bundlePath string, opts VerifyOpts) error
}

// SignOpts contains the options for a cosign sign-blob invocation.
type SignOpts struct {
	BundleOutPath string
	IdentityToken string
	FulcioURL     string
	RekorURL      string
	TSAURL        string
}

// VerifyOpts contains the options for a cosign verify-blob invocation.
type VerifyOpts struct {
	CertificateIdentity         string
	CertificateIdentityRegexp   string
	CertificateOIDCIssuer       string
	CertificateOIDCIssuerRegexp string
	TrustedRoot                 string
}

// DefaultExecutor invokes the cosign binary via os/exec.
type DefaultExecutor struct {
	binaryPath string

	checkOnce sync.Once
	checkErr  error
}

// NewDefaultExecutor returns an executor that shells out to the cosign binary in PATH.
func NewDefaultExecutor() *DefaultExecutor {
	return &DefaultExecutor{binaryPath: "cosign"}
}

// ensureCosignAvailable checks that the cosign binary exists on PATH.
// The check runs at most once; subsequent calls return the cached result.
func (e *DefaultExecutor) ensureCosignAvailable() error {
	e.checkOnce.Do(func() {
		path, err := exec.LookPath(e.binaryPath)
		if err != nil {
			e.checkErr = fmt.Errorf(
				"cosign binary not found on PATH: install cosign from "+
					"https://github.com/sigstore/cosign?tab=readme-ov-file#installation "+
					"and ensure it is on PATH: %w", err)
			return
		}
		e.binaryPath = path
	})
	return e.checkErr
}

// ensureDeadline returns a context with a deadline. If the parent context already
// has a deadline, it is returned as-is. Otherwise a default timeout is applied.
func ensureDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultOperationTimeout) //nolint:gosec // G118: cancel is returned to caller
}

func (e *DefaultExecutor) SignBlob(ctx context.Context, dataPath string, opts SignOpts) ([]byte, error) {
	if err := e.ensureCosignAvailable(); err != nil {
		return nil, err
	}

	args := []string{
		"sign-blob", dataPath,
		"--bundle", opts.BundleOutPath,
		"--identity-token", opts.IdentityToken,
		"--yes",
	}
	if opts.FulcioURL != "" {
		args = append(args, "--fulcio-url", opts.FulcioURL)
	}
	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}
	if opts.TSAURL != "" {
		args = append(args, "--timestamp-server-url", opts.TSAURL)
	}

	ctx, cancel := ensureDeadline(ctx)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...) //nolint:gosec // G204: args are constructed from trusted config, not user input
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, cosignError("sign-blob", err, ctx.Err(), stderr.Bytes())
	}

	bundleJSON, err := os.ReadFile(opts.BundleOutPath)
	if err != nil {
		return nil, fmt.Errorf("read bundle output: %w", err)
	}

	return bundleJSON, nil
}

func (e *DefaultExecutor) VerifyBlob(ctx context.Context, dataPath, bundlePath string, opts VerifyOpts) error {
	if err := e.ensureCosignAvailable(); err != nil {
		return err
	}

	args := []string{"verify-blob", dataPath, "--bundle", bundlePath}

	if opts.CertificateIdentity != "" {
		args = append(args, "--certificate-identity", opts.CertificateIdentity)
	}
	if opts.CertificateIdentityRegexp != "" {
		args = append(args, "--certificate-identity-regexp", opts.CertificateIdentityRegexp)
	}
	if opts.CertificateOIDCIssuer != "" {
		args = append(args, "--certificate-oidc-issuer", opts.CertificateOIDCIssuer)
	}
	if opts.CertificateOIDCIssuerRegexp != "" {
		args = append(args, "--certificate-oidc-issuer-regexp", opts.CertificateOIDCIssuerRegexp)
	}
	if opts.TrustedRoot != "" {
		args = append(args, "--trusted-root", opts.TrustedRoot)
	}

	ctx, cancel := ensureDeadline(ctx)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...) //nolint:gosec // G204: args are constructed from trusted config, not user input
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return cosignError("verify-blob", err, ctx.Err(), stderr.Bytes())
	}

	return nil
}

// cosignError builds a descriptive error from a failed cosign invocation.
// It includes the subcommand name, the first 1024 bytes of stderr, and
// distinguishes between context deadline exceeded and other failures.
func cosignError(subcommand string, execErr, ctxErr error, stderr []byte) error {
	const maxStderr = 1024

	msg := strings.TrimSpace(string(limitBytes(stderr, maxStderr)))

	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return fmt.Errorf("cosign %s timed out: %w\nstderr: %s", subcommand, execErr, msg)
	}

	return fmt.Errorf("cosign %s failed: %w\nstderr: %s", subcommand, execErr, msg)
}

func limitBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

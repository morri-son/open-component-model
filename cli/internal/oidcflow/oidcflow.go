// Package oidcflow implements an interactive OIDC authorization code flow
// with PKCE for acquiring ID tokens from an OIDC provider.
//
// It opens a browser for user authentication, handles the callback via a
// local HTTP server, and exchanges the authorization code for an ID token.
// This is the same flow used by Sigstore for keyless signing, implemented
// without depending on github.com/sigstore/sigstore.
package oidcflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	DefaultIssuer   = "https://oauth2.sigstore.dev/auth"
	DefaultClientID = "sigstore"

	callbackPath    = "/auth/callback"
	callbackTimeout = 120 * time.Second
)

// Token holds the raw OIDC ID token string after a successful flow.
type Token struct {
	RawToken string
}

// Options configures the OIDC flow.
type Options struct {
	Issuer   string
	ClientID string
}

func (o *Options) issuer() string {
	if o.Issuer != "" {
		return o.Issuer
	}
	return DefaultIssuer
}

func (o *Options) clientID() string {
	if o.ClientID != "" {
		return o.ClientID
	}
	return DefaultClientID
}

// GetIDToken performs an interactive OIDC authorization code flow with PKCE.
// It opens the user's browser for authentication and waits for the callback.
func GetIDToken(ctx context.Context, opts Options) (*Token, error) {
	provider, err := oidc.NewProvider(ctx, opts.issuer())
	if err != nil {
		return nil, fmt.Errorf("oidc provider discovery: %w", err)
	}

	pkce, err := newPKCE(provider)
	if err != nil {
		return nil, err
	}

	state, err := randomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}
	nonce, err := randomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("start callback listener: %w", err)
	}

	addr := listener.Addr().(*net.TCPAddr)
	redirectURL := fmt.Sprintf("http://localhost:%d%s", addr.Port, callbackPath)

	srv := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           callbackHandler(state, codeCh, errCh),
	}
	go func() {
		if sErr := srv.Serve(listener); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			errCh <- sErr
		}
	}()
	defer func() {
		go func() { _ = srv.Shutdown(context.Background()) }()
	}()

	config := oauth2.Config{
		ClientID:    opts.clientID(),
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "email"},
		RedirectURL: redirectURL,
	}

	authOpts := append(pkce.authURLOpts(),
		oauth2.AccessTypeOnline,
		oidc.Nonce(nonce),
	)
	authURL := config.AuthCodeURL(state, authOpts...)

	if err := openBrowser(ctx, authURL); err != nil {
		return nil, fmt.Errorf("open browser: %w (URL: %s)", err, authURL)
	}

	code, err := waitForCode(codeCh, errCh)
	if err != nil {
		return nil, fmt.Errorf("receive auth callback: %w", err)
	}

	token, err := config.Exchange(ctx, code, append(pkce.tokenURLOpts(), oidc.Nonce(nonce))...)
	if err != nil {
		return nil, fmt.Errorf("exchange code for token: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token not present in token response")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, errors.New("nonce mismatch in id token")
	}

	return &Token{RawToken: rawIDToken}, nil
}

func callbackHandler(expectedState string, codeCh chan<- string, errCh chan<- error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB limit
		if r.FormValue("state") != expectedState {
			errCh <- errors.New("invalid state parameter in callback")
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		codeCh <- r.FormValue("code")
		fmt.Fprint(w, successHTML)
	})
	return mux
}

func waitForCode(codeCh <-chan string, errCh <-chan error) (string, error) {
	timer := time.NewTimer(callbackTimeout)
	defer timer.Stop()
	select {
	case code := <-codeCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-timer.C:
		return "", errors.New("timed out waiting for authentication callback")
	}
}

// pkce implements Proof Key for Code Exchange (RFC 7636).
type pkce struct {
	challenge string
	verifier  string
}

func newPKCE(provider *oidc.Provider) (*pkce, error) {
	var claims struct {
		Methods []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse provider claims: %w", err)
	}

	supported := false
	for _, m := range claims.Methods {
		if m == "S256" {
			supported = true
			break
		}
	}
	if !supported {
		return nil, fmt.Errorf("OIDC provider %s does not support PKCE S256", provider.Endpoint().AuthURL)
	}

	verifier, err := randomString(64)
	if err != nil {
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}

	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &pkce{challenge: challenge, verifier: verifier}, nil
}

func (p *pkce) authURLOpts() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", p.challenge),
	}
}

func (p *pkce) tokenURLOpts() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", p.verifier),
	}
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// successHTML is the page shown in the browser after successful OIDC authentication.
// Layout and animations are based on the Sigstore interactive success page, branded with the OCM logo.
const successHTML = `<!DOCTYPE html>
<html>
	<head>
		<title>OCM Authentication</title>
		<link id="favicon" rel="icon" type="image/svg+xml"/>
		<style>
			:root { font-family: "Trebuchet MS", sans-serif; height: 100%; color: #2e3440; overflow: hidden; }
			body { display: flex; justify-content: center; height: 100%; margin: 0 10%; background: #f0f4fa; }
			.container { display: flex; flex-direction: column; justify-content: space-between; }
			.ocm { color: #2e5b9d; font-weight: bold; }
			.header { position: absolute; top: 30px; left: 22px; display: flex; align-items: center; gap: 12px; text-decoration: none; }
			.header-text { font-size: 1.2em; font-weight: bold; color: #2e5b9d; }
			.title { font-size: 3.5em; margin-bottom: 30px; animation: 750ms ease-in-out 0s 1 show; }
			.content { font-size: 1.5em; animation: 250ms hide, 750ms ease-in-out 250ms 1 show; }
			.anchor { position: relative; }
			.links { display: flex; justify-content: space-between; font-size: 1.2em; padding: 60px 0; position: absolute; bottom: 0; left: 0; right: 0; animation: 500ms hide, 750ms ease-in-out 500ms 1 show; }
			.link { color: #2e3440; text-decoration: none; user-select: none; }
			.link:hover { color: #407bd4; }
			.link:hover>.arrow { transform: scaleX(1.5) translateX(3px); }
			.link:hover>.ocm { color: inherit; }
			.link, .arrow { transition: 200ms; }
			.arrow { display: inline-block; margin-left: 6px; transform: scaleX(1.5); }
			@keyframes hide { 0%, 100% { opacity: 0; } }
			@keyframes show { 0% { opacity: 0; transform: translateY(40px); } 100% { opacity: 1; } }
		</style>
	</head>
	<body>
		<div class="container">
			<div>
				<a class="header" href="https://ocm.software">
					<svg id="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 145.4 145.4" width="36" height="36">
						<defs>
							<linearGradient id="g" x1="3348.8" y1="2398.7" x2="3348.9" y2="2398.7" gradientTransform="matrix(338.03 313.02 313.02 -338.03 -1882854 -236563)" gradientUnits="userSpaceOnUse">
								<stop offset="0" stop-color="#2e5b9d"/><stop offset="1" stop-color="#3b72c7"/>
							</linearGradient>
						</defs>
						<path fill="#407bd4" d="M98.2 3.6C93.7 2 89.1.7 84.4 0l-4.6 5.1c-5-.5-10-.5-14.9 0l-4.7-5C55.5.9 50.9 2.2 46.5 3.9L45 10.6c-4.6 2-8.9 4.6-12.9 7.5l-6.5-2c-3.7 3-7 6.4-10 10.1l2.1 6.5c-2.9 4-5.4 8.4-7.4 13L3.6 47.2C2 51.7.7 56.3 0 61l5.1 4.6c-.5 5-.5 10 0 14.9l-5 4.7c.8 4.7 2.1 9.3 3.8 13.7l6.7 1.5c2 4.6 4.6 8.9 7.5 12.9l-2 6.5c3 3.7 6.4 7 10.1 10l6.5-2.1c4 2.9 8.4 5.4 13 7.4l1.5 6.7c4.5 1.6 9.1 2.9 13.8 3.6l4.6-5.1c5 .5 10 .5 14.9 0l4.7 5c4.7-.8 9.3-2.1 13.7-3.8l1.5-6.7c4.6-2 8.9-4.6 12.9-7.5l6.5 2c3.7-3 7-6.4 10-10.1l-2.1-6.5c2.9-4 5.4-8.4 7.4-13l6.7-1.5c1.6-4.5 2.9-9.1 3.6-13.8l-5.1-4.6c.5-5 .5-10 0-14.9l5-4.7c-.8-4.7-2.1-9.3-3.8-13.7L134.8 45c-2-4.6-4.6-8.9-7.5-12.9l2-6.5c-3-3.7-6.4-7-10.1-10l-6.5 2.1c-4-2.9-8.4-5.4-13-7.4z"/>
						<path fill="url(#g)" d="M68.7 140.7 29.9 103.5l35.2-27-13.2-12 42.3-22.8 49.6 50.3c-.6 2.1-1.2 4.2-2 6.2l-6.7 1.5c-2 4.6-4.5 8.9-7.4 13l2.1 6.5c-3 3.7-6.4 7.1-10 10.1l-6.5-2c-4 3-8.3 5.5-12.9 7.5l-1.5 6.7c-4.4 1.7-9 3-13.7 3.8l-4.7-5c-4 .5-8 .6-11.9.3z"/>
						<path fill="#fff" d="m64.9 74.9c0 .1.1.2.2.3 1.1.6 6.9 4 6.9 4v7.4c0 0 0 .1 0 .2v.3c-.6 1-1.7 1.5-2.7 1.2L68 88c-1.1-.3-2.2 0-3.1.6-.9.7-1.4 1.7-1.4 2.9v0c0 1.1.5 2.2 1.4 2.9.9.7 2 .9 3.1.6l1.4-.4c1-.3 2 .2 2.4 1.1l.2.4c0 0 0 .1 0 .2v7.4L50.9 115.9 29.8 103.7V79.4L50.9 67.2c0 0 6.6 3.8 7.7 4.4 0 0 .2 0 .3 0 .8-.2 1.4-.5 2-.9 1.1-.6 1.9-1.6 1.9-2.8 0 0 0 0 0 0 0-.7.3-1.3.9-1.6.6-.4 1.2-.5 1.9-.3.3.1.6.3.8.5.5.4.8 1.2.7 1.9-.1.7-.4 1.2-1 1.5-1.1.6-1.6 1.8-1.6 3 0 .7 0 1.5.3 2.2z"/>
						<path fill="#fff" d="m80.4 74.1c-.1 0-.2 0-.3 0-1.1.6-6.9 4-6.9 4l-6.4-3.7c0 0 0 0-.1-.1L66.5 74.1c-.6-.9-.5-2.1.2-2.9l.9-.9c.8-.8 1.2-1.9 1-3-.1-1.1-.8-2.1-1.8-2.6v0c-1-.6-2.1-.6-3.2-.2-1 .4-1.8 1.3-2.1 2.4l-.4 1.4c-.3 1-1.2 1.6-2.2 1.5h-.4c0 0-.2 0-.2-.1L51.9 66V41.7c0 0 21.1-12.2 21.1-12.2L94.1 41.7V66c0 0-6.6 3.8-7.7 4.4 0 0-.2.2-.2.3-.2.8-.3 1.5-.2 2.2.2 1.2.5 2.5 1.5 3.1 0 0 0 0 0 0 .6.3.9.9 1 1.6 0 .7-.1 1.3-.6 1.8-.3.2-.5.4-.9.5-.6.2-1.4 0-2-.3-.6-.3-.8-1-.8-1.6 0-1.2-.8-2.3-1.8-2.9-.6-.3-1.3-.7-2.1-.9z"/>
						<path fill="#fff" d="m73.3 87.9c0 0 .1-.2.1-.3 0-1.2 0-8 0-8l6.4-3.7c0 0 .1 0 .2 0h.3c1.1-.1 2.1.6 2.4 1.6l.3 1.3c.3 1.1 1.1 2 2.1 2.4 1 .4 2.2.3 3.2-.2v0c1-.6 1.6-1.5 1.8-2.6.1-1.1-.2-2.2-1-3l-1-1c-.7-.7-.8-1.8-.2-2.7l.2-.3c0 0 .1-.1.2-.2l6.4-3.7 21.1 12.1v24.3c0 0-21 12.2-21 12.2L73.7 104c0 0 0-7.6 0-8.9 0-.1 0-.2-.1-.3-.5-.6-1-1.1-1.6-1.4-.7-.4-2.5-.7-3.6 0 0 0 0 0 0 0-.6.3-1.3.3-1.9 0-.6-.3-1.1-.8-1.2-1.4 0-.3 0-.7 0-1 .1-.6.7-1.3 1.3-1.5.6-.2 1.3-.3 1.8 0 1.1.6 2.4.5 3.4-.1C72.4 89 73 88.6 73.6 88z"/>
					</svg>
					<span class="header-text">Open Component Model</span>
				</a>
			</div>
			<div>
				<div class="title">
					<span class="ocm">OCM </span>
					<span>authentication successful!</span>
				</div>
				<div class="content">
					<span>You may now close this page.</span>
				</div>
			</div>
			<div class="anchor">
				<div class="links">
					<a href="https://ocm.software/" class="link"><span class="ocm">OCM</span> home <span class="arrow">&#x2192;</span></a>
					<a href="https://ocm.software/docs/" class="link"><span class="ocm">OCM</span> documentation <span class="arrow">&#x2192;</span></a>
					<a href="https://ocm.software/blog/" class="link"><span class="ocm">OCM</span> blog <span class="arrow">&#x2192;</span></a>
				</div>
			</div>
		</div>
		<script>
			document.getElementById("favicon").setAttribute("href", "data:image/svg+xml," + encodeURIComponent(document.getElementById("logo").outerHTML));
		</script>
	</body>
</html>
`

func openBrowser(ctx context.Context, url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(ctx, "open", url).Start()
	case "linux":
		return exec.CommandContext(ctx, "xdg-open", url).Start()
	case "windows":
		return exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

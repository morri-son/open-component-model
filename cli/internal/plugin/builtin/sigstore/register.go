package sigstore

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"ocm.software/open-component-model/bindings/go/plugin/manager/registries/signinghandler"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler"
)

const (
	defaultOIDCIssuer   = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID = "sigstore"
)

// interactiveTokenGetter acquires an OIDC identity token for keyless Sigstore signing.
// It checks the SIGSTORE_ID_TOKEN environment variable first (for CI), then falls back
// to an interactive browser-based OIDC flow against the public-good Sigstore issuer.
type interactiveTokenGetter struct{}

func (g *interactiveTokenGetter) GetIDToken() (string, error) {
	if tok := os.Getenv("SIGSTORE_ID_TOKEN"); tok != "" {
		return tok, nil
	}
	result, err := oauthflow.OIDConnect(defaultOIDCIssuer, defaultOIDCClientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return "", fmt.Errorf("interactive OIDC authentication: %w", err)
	}
	return result.RawString, nil
}

func Register(signingHandlerRegistry *signinghandler.SigningRegistry) error {
	hdlr := handler.NewWithTokenGetter(&interactiveTokenGetter{})

	return signingHandlerRegistry.RegisterInternalComponentSignatureHandler(hdlr)
}

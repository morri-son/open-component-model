package sigstore

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"ocm.software/open-component-model/bindings/go/plugin/manager/registries/signinghandler"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

// interactiveTokenGetter acquires an OIDC identity token for keyless Sigstore signing.
// It checks the SIGSTORE_ID_TOKEN environment variable first (for CI), then falls back
// to an interactive browser-based OIDC flow against the given issuer.
type interactiveTokenGetter struct{}

func (g *interactiveTokenGetter) GetIDToken(issuer, clientID string) (string, error) {
	if tok := os.Getenv("SIGSTORE_ID_TOKEN"); tok != "" {
		return tok, nil
	}
	result, err := oauthflow.OIDConnect(issuer, clientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return "", fmt.Errorf("interactive OIDC authentication: %w", err)
	}
	return result.RawString, nil
}

func Register(signingHandlerRegistry *signinghandler.SigningRegistry) error {
	scheme := runtime.NewScheme()
	if err := scheme.RegisterScheme(v1alpha1.Scheme); err != nil {
		return err
	}

	hdlr := handler.NewWithTokenGetter(scheme, &interactiveTokenGetter{})

	return signingHandlerRegistry.RegisterInternalComponentSignatureHandler(hdlr)
}

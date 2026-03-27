package handler

import (
	"context"
	"fmt"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/signing"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

var _ signing.Handler = (*Handler)(nil)

const (
	IdentityAttributeAlgorithm = "algorithm"
	IdentityAttributeSignature = "signature"
)

// TokenGetter acquires an OIDC identity token for keyless signing.
// The issuer and clientID parameters identify the OIDC provider to authenticate against.
type TokenGetter interface {
	GetIDToken(issuer, clientID string) (string, error)
}

type Handler struct {
	tokenGetter TokenGetter
}

func New() *Handler {
	return &Handler{}
}

// NewWithTokenGetter creates a Handler with an interactive token acquisition flow.
// When no private key or OIDC token is available from credentials, the handler
// calls tg.GetIDToken to obtain a token (e.g. via browser-based OIDC).
func NewWithTokenGetter(tg TokenGetter) *Handler {
	return &Handler{tokenGetter: tg}
}

func (h *Handler) GetSigningHandlerScheme() *runtime.Scheme {
	return v1alpha1.Scheme
}

func (h *Handler) Sign(
	ctx context.Context,
	unsigned descruntime.Digest,
	rawCfg runtime.Typed,
	creds map[string]string,
) (descruntime.SignatureInfo, error) {
	return signWithConfig(ctx, unsigned, rawCfg, creds, h.GetSigningHandlerScheme(), h.tokenGetter)
}

func (h *Handler) Verify(
	ctx context.Context,
	signed descruntime.Signature,
	rawCfg runtime.Typed,
	creds map[string]string,
) error {
	return verifyWithConfig(ctx, signed, rawCfg, creds, h.GetSigningHandlerScheme())
}

func (*Handler) GetSigningCredentialConsumerIdentity(
	_ context.Context,
	name string,
	_ descruntime.Digest,
	rawCfg runtime.Typed,
) (runtime.Identity, error) {
	var cfg v1alpha1.Config
	if err := v1alpha1.Scheme.Convert(rawCfg, &cfg); err != nil {
		return nil, fmt.Errorf("convert config: %w", err)
	}
	id := baseIdentity()
	id[IdentityAttributeSignature] = name
	return id, nil
}

func (*Handler) GetVerifyingCredentialConsumerIdentity(
	_ context.Context,
	signature descruntime.Signature,
	_ runtime.Typed,
) (runtime.Identity, error) {
	if signature.Signature.MediaType != v1alpha1.MediaTypeSigstoreBundle {
		return nil, fmt.Errorf("unsupported media type %q for sigstore verification", signature.Signature.MediaType)
	}
	id := baseIdentity()
	id[IdentityAttributeSignature] = signature.Name
	return id, nil
}

func baseIdentity() runtime.Identity {
	id := runtime.Identity{IdentityAttributeAlgorithm: v1alpha1.AlgorithmSigstore}
	id.SetType(credentials.IdentityTypeSigstore)
	return id
}

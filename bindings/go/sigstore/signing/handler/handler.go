package handler

import (
	"context"
	"errors"
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

var ErrMissingCredentials = errors.New("either a private key or OIDC token must be provided for signing")

type Handler struct {
	scheme *runtime.Scheme
}

func New(scheme *runtime.Scheme) *Handler {
	return &Handler{scheme: scheme}
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
	return signWithConfig(ctx, unsigned, rawCfg, creds, h.GetSigningHandlerScheme())
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

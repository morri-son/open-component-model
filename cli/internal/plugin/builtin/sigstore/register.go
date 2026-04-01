package sigstore

import (
	"ocm.software/open-component-model/bindings/go/plugin/manager/registries/signinghandler"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler"
)

func Register(signingHandlerRegistry *signinghandler.SigningRegistry) error {
	return signingHandlerRegistry.RegisterInternalComponentSignatureHandler(handler.New())
}

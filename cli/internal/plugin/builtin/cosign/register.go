package cosign

import (
	"ocm.software/open-component-model/bindings/go/cosign/signing/handler"
	"ocm.software/open-component-model/bindings/go/plugin/manager/registries/signinghandler"
)

// Register registers the cosign CLI-based signing handler with the signing registry.
func Register(signingHandlerRegistry *signinghandler.SigningRegistry) error {
	return signingHandlerRegistry.RegisterInternalComponentSignatureHandler(handler.New())
}

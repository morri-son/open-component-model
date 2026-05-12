package credentialplugin

import (
	"context"
	"fmt"

	"ocm.software/open-component-model/bindings/go/credentials"
	v1 "ocm.software/open-component-model/bindings/go/plugin/manager/contracts/credentialplugin/v1"
	"ocm.software/open-component-model/bindings/go/runtime"
)

type credentialPluginConverter struct {
	externalPlugin v1.CredentialPluginContract[runtime.Typed]
}

var _ credentials.CredentialPlugin = (*credentialPluginConverter)(nil)

func newCredentialPluginConverter(plugin v1.CredentialPluginContract[runtime.Typed]) credentials.CredentialPlugin {
	return &credentialPluginConverter{
		externalPlugin: plugin,
	}
}

func (c *credentialPluginConverter) GetConsumerIdentity(ctx context.Context, credential runtime.Typed) (runtime.Identity, error) {
	request := v1.GetConsumerIdentityRequest[runtime.Typed]{
		Credential: credential,
	}
	identity, err := c.externalPlugin.GetConsumerIdentity(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get consumer identity: %w", err)
	}
	return identity, nil
}

func (c *credentialPluginConverter) Resolve(ctx context.Context, identity runtime.Identity, credentials map[string]string) (map[string]string, error) {
	request := v1.ResolveRequest[runtime.Typed]{
		Identity: identity,
	}
	resolvedCredentials, err := c.externalPlugin.Resolve(ctx, request, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve credentials: %w", err)
	}
	return resolvedCredentials, nil
}

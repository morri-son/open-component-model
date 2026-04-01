package sigstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"ocm.software/open-component-model/bindings/go/runtime"
)

func Test_OIDCPlugin_GetConsumerIdentity(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	plugin := &OIDCPlugin{}

	raw := &runtime.Raw{}
	raw.SetType(OIDCPluginTypeVersioned)
	raw.Data = []byte(`{"type":"SigstoreOIDC/v1alpha1","issuer":"https://custom.issuer.dev","clientID":"my-client"}`)

	id, err := plugin.GetConsumerIdentity(t.Context(), raw)
	r.NoError(err)
	r.Equal("https://custom.issuer.dev", id[configKeyIssuer])

	idType, err := id.ParseType()
	r.NoError(err)
	r.Equal(OIDCPluginTypeVersioned, idType)
}

func Test_OIDCPlugin_GetConsumerIdentity_Defaults(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	plugin := &OIDCPlugin{}

	raw := &runtime.Raw{}
	raw.SetType(OIDCPluginTypeVersioned)
	raw.Data = []byte(`{"type":"SigstoreOIDC/v1alpha1"}`)

	id, err := plugin.GetConsumerIdentity(t.Context(), raw)
	r.NoError(err)
	r.Equal(defaultOIDCIssuer, id[configKeyIssuer])
}

func Test_OIDCPlugin_Resolve_EnvVar(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "env-token")
	r := require.New(t)

	plugin := &OIDCPlugin{}

	id := runtime.Identity{configKeyIssuer: defaultOIDCIssuer}
	id.SetType(OIDCPluginTypeVersioned)

	creds, err := plugin.Resolve(t.Context(), id, nil)
	r.NoError(err)
	r.Equal("env-token", creds[credentialKeyOIDCToken])
}

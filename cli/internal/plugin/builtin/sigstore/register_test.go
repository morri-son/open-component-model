package sigstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_InteractiveTokenGetter_EnvVar(t *testing.T) {
	t.Run("SIGSTORE_ID_TOKEN env var is used when set", func(t *testing.T) {
		t.Setenv("SIGSTORE_ID_TOKEN", "env-token")
		r := require.New(t)

		g := &interactiveTokenGetter{}
		token, err := g.GetIDToken()
		r.NoError(err)
		r.Equal("env-token", token)
	})

	t.Run("credential token from env var takes priority over browser flow", func(t *testing.T) {
		t.Setenv("SIGSTORE_ID_TOKEN", "env-token-priority")
		r := require.New(t)

		g := &interactiveTokenGetter{}
		token, err := g.GetIDToken()
		r.NoError(err)
		r.Equal("env-token-priority", token)
	})
}

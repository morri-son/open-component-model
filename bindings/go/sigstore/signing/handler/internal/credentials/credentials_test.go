package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_OIDCTokenFromCredentials(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	r.Equal("my-token", OIDCTokenFromCredentials(map[string]string{
		CredentialKeyOIDCToken: "my-token",
	}))
	r.Equal("", OIDCTokenFromCredentials(map[string]string{}))
}

func Test_TrustedRootFromCredentials(t *testing.T) {
	t.Parallel()

	t.Run("inline JSON", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := TrustedRootFromCredentials(map[string]string{
			CredentialKeyTrustedRootJSON: `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`,
		})
		r.NoError(err)
		r.Contains(string(result), "trustedroot")
	})

	t.Run("file path", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		path := filepath.Join(t.TempDir(), "trusted_root.json")
		r.NoError(os.WriteFile(path, []byte(`{"test":"data"}`), 0o600))
		result, err := TrustedRootFromCredentials(map[string]string{
			CredentialKeyTrustedRootJSONFile: path,
		})
		r.NoError(err)
		r.Equal(`{"test":"data"}`, string(result))
	})

	t.Run("empty returns nil", func(t *testing.T) {
		t.Parallel()
		r := require.New(t)
		result, err := TrustedRootFromCredentials(map[string]string{})
		r.NoError(err)
		r.Nil(result)
	})
}

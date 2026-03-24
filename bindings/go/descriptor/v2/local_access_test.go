package v2_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	descriptorv2 "ocm.software/open-component-model/bindings/go/descriptor/v2"
	"ocm.software/open-component-model/bindings/go/runtime"
)

func TestLocalBlob_Struct(t *testing.T) {
	// Setup
	globalAccess := &runtime.Raw{
		Type: runtime.Type{
			Name: "OCIImage",
		},
		Data: []byte(`{"type":"OCIImage","imageReference":"test/image:1.0"}`),
	}

	blob := descriptorv2.LocalBlob{
		Type: runtime.Type{
			Name:    descriptorv2.LocalBlobAccessType,
			Version: descriptorv2.LocalBlobAccessTypeVersion,
		},
		LocalReference: "sha256:abc123",
		MediaType:      "application/octet-stream",
		GlobalAccess:   globalAccess,
		ReferenceName:  "test/repo:1.0",
	}

	// Test
	jsonData, err := json.Marshal(blob)

	// Assert
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), `"type":"LocalBlob/v1"`)
	assert.Contains(t, string(jsonData), `"localReference":"sha256:abc123"`)
	assert.Contains(t, string(jsonData), `"mediaType":"application/octet-stream"`)
	assert.Contains(t, string(jsonData), `"globalAccess":{"type":"OCIImage","imageReference":"test/image:1.0"}`)
	assert.Contains(t, string(jsonData), `"referenceName":"test/repo:1.0"`)
}

func TestLocalBlob_UnmarshalJSON(t *testing.T) {
	// Setup — uses new UpperCamelCase primary type
	jsonData := `{
		"type": "LocalBlob/v1",
		"localReference": "sha256:abc123",
		"mediaType": "application/octet-stream",
		"globalAccess": {
			"type": "OCIImage",
			"imageReference": "test/image:1.0"
		},
		"referenceName": "test/repo:1.0"
	}`

	var blob descriptorv2.LocalBlob
	err := json.Unmarshal([]byte(jsonData), &blob)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, descriptorv2.LocalBlobAccessType, blob.Type.Name)
	assert.Equal(t, descriptorv2.LocalBlobAccessTypeVersion, blob.Type.Version)
	assert.Equal(t, "sha256:abc123", blob.LocalReference)
	assert.Equal(t, "application/octet-stream", blob.MediaType)
	assert.Equal(t, "test/repo:1.0", blob.ReferenceName)
	require.NotNil(t, blob.GlobalAccess)
	assert.Equal(t, "OCIImage", blob.GlobalAccess.Type.Name)
}

func TestLocalBlob_UnmarshalJSON_Legacy(t *testing.T) {
	// Setup — uses legacy lowerCamelCase form (backward compatibility)
	jsonData := `{
		"type": "localBlob/v1",
		"localReference": "sha256:abc123",
		"mediaType": "application/octet-stream",
		"globalAccess": {
			"type": "OCIImage",
			"imageReference": "test/image:1.0"
		},
		"referenceName": "test/repo:1.0"
	}`

	var blob descriptorv2.LocalBlob
	err := json.Unmarshal([]byte(jsonData), &blob)

	// Assert — raw JSON unmarshal preserves the original type name
	require.NoError(t, err)
	assert.Equal(t, descriptorv2.LegacyLocalBlobAccessType, blob.Type.Name)
	assert.Equal(t, descriptorv2.LocalBlobAccessTypeVersion, blob.Type.Version)
	assert.Equal(t, "sha256:abc123", blob.LocalReference)
	assert.Equal(t, "application/octet-stream", blob.MediaType)
	assert.Equal(t, "test/repo:1.0", blob.ReferenceName)
	require.NotNil(t, blob.GlobalAccess)
	assert.Equal(t, "OCIImage", blob.GlobalAccess.Type.Name)
}

func TestLocalBlob_UnmarshalJSON_Minimal(t *testing.T) {
	// Setup — uses new UpperCamelCase primary type
	jsonData := `{
		"type": "LocalBlob/v1",
		"localReference": "sha256:abc123",
		"mediaType": "application/octet-stream"
	}`

	var blob descriptorv2.LocalBlob
	err := json.Unmarshal([]byte(jsonData), &blob)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, descriptorv2.LocalBlobAccessType, blob.Type.Name)
	assert.Equal(t, descriptorv2.LocalBlobAccessTypeVersion, blob.Type.Version)
	assert.Equal(t, "sha256:abc123", blob.LocalReference)
	assert.Equal(t, "application/octet-stream", blob.MediaType)
	assert.Nil(t, blob.GlobalAccess)
	assert.Empty(t, blob.ReferenceName)
}

func TestLocalBlob_Constants(t *testing.T) {
	// Test access type constants
	assert.Equal(t, "LocalBlob", descriptorv2.LocalBlobAccessType)
	assert.Equal(t, "localBlob", descriptorv2.LegacyLocalBlobAccessType)
	assert.Equal(t, "v1", descriptorv2.LocalBlobAccessTypeVersion)
}

package component_version

import "fmt"

type UploadAs int

const (
	// UploadAsDefault is the default upload mode, which is determined by the source and target repository.
	UploadAsDefault UploadAs = iota
	// UploadAsLocalBlob sets the upload of all oci resources as local blobs.
	UploadAsLocalBlob
	// UploadAsOciArtifact sets the upload of all oci resources as OCI artifacts.
	UploadAsOciArtifact
)

func (o UploadAs) String() string {
	switch o {
	case UploadAsDefault:
		return "default"
	case UploadAsLocalBlob:
		return "LocalBlob"
	case UploadAsOciArtifact:
		return "OCIArtifact"
	default:
		return fmt.Sprintf("unknown(%d)", o)
	}
}

const (
	// LegacyUploadAsLocalBlob is the legacy flag value for uploading as local blobs.
	LegacyUploadAsLocalBlob = "localBlob"
	// LegacyUploadAsOciArtifact is the legacy flag value for uploading as OCI artifacts.
	LegacyUploadAsOciArtifact = "ociArtifact"
)

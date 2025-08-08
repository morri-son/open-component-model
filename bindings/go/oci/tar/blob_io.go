package tar

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	ociImageSpecV1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"ocm.software/open-component-model/bindings/go/blob"
	"ocm.software/open-component-model/bindings/go/blob/inmemory"
	"ocm.software/open-component-model/bindings/go/oci/spec/layout"
)

type CopyToOCILayoutOptions struct {
	oras.CopyGraphOptions
	Tags []string
}

// CopyToOCILayoutInMemory streams the contents of an OCI graph from the given
// ReadOnlyStorage into an in-memory OCI layout archive (gzipped tar), returning
// a Blob that can be read by consumers. The actual copy happens asynchronously
// in a goroutine; if the caller never reads from the returned Blob, the copy
// will block.
//
// Returns an inmemory.Blob wrapping the read side of a pipe, with media type
// [layout.MediaTypeOCIImageLayoutTarGzipV1].
func CopyToOCILayoutInMemory(ctx context.Context, src content.ReadOnlyStorage, base ociImageSpecV1.Descriptor, opts CopyToOCILayoutOptions) (*inmemory.Blob, error) {
	r, w := io.Pipe()

	go copyToOCILayoutInMemoryAsync(ctx, src, base, opts, w)

	downloaded := inmemory.New(r, inmemory.WithMediaType(layout.MediaTypeOCIImageLayoutTarGzipV1))
	return downloaded, nil
}

// copyToOCILayoutInMemoryAsync performs the actual OCI‐layout archive creation
// and writes it into the provided PipeWriter. Any error (from CopyGraph,
// gzip, or OCILayoutWriter) is joined and propagated via the pipe's [io.PipeWriter.CloseWithError],
// causing any reader to receive an error when reading from the pipe.
func copyToOCILayoutInMemoryAsync(ctx context.Context, src content.ReadOnlyStorage, base ociImageSpecV1.Descriptor, opts CopyToOCILayoutOptions, w *io.PipeWriter) {
	// err accumulates any error from copy, gzip, or layout writing.
	var err error
	defer func() {
		w.CloseWithError(err)
	}()

	zippedBuf := gzip.NewWriter(w)
	defer func() {
		err = errors.Join(err, zippedBuf.Close())
	}()

	// Create an OCI layout writer over the gzip stream.
	target := NewOCILayoutWriter(zippedBuf)
	defer func() {
		err = errors.Join(err, target.Close())
	}()

	// Copy the image graph into the layout.
	if err = errors.Join(err, oras.CopyGraph(ctx, src, target, base, opts.CopyGraphOptions)); err != nil {
		return
	}

	// Apply any additional tags.
	for _, tag := range opts.Tags {
		if err = errors.Join(err, target.Tag(ctx, base, tag)); err != nil {
			return
		}
	}
}

type CopyOCILayoutWithIndexOptions struct {
	oras.CopyGraphOptions
	MutateParentFunc func(*ociImageSpecV1.Descriptor) error
}

func CopyOCILayoutWithIndex(ctx context.Context, dst content.Storage, src blob.ReadOnlyBlob, opts CopyOCILayoutWithIndexOptions) (top ociImageSpecV1.Descriptor, err error) {
	ociStore, err := ReadOCILayout(ctx, src)
	if err != nil {
		return ociImageSpecV1.Descriptor{}, fmt.Errorf("failed to read OCI layout: %w", err)
	}
	defer func() {
		err = errors.Join(err, ociStore.Close())
	}()

	index, proxy, err := proxyOCIStore(ctx, ociStore, &opts)
	if err != nil {
		return ociImageSpecV1.Descriptor{}, fmt.Errorf("failed to create proxy for OCI store: %w", err)
	}

	if err := oras.CopyGraph(ctx, proxy, dst, index, opts.CopyGraphOptions); err != nil {
		return ociImageSpecV1.Descriptor{}, fmt.Errorf("failed to copy graph for index from oci layout %v: %w", index, err)
	}

	return index, nil
}

func proxyOCIStore(ctx context.Context, ociStore *CloseableReadOnlyStore, opts *CopyOCILayoutWithIndexOptions) (ociImageSpecV1.Descriptor, content.ReadOnlyStorage, error) {
	// if our store only has one single manifest, we dont need to copy the index, instead we can use the manifest as is.
	if len(ociStore.Index.Manifests) == 1 {
		return proxyOCIStoreWithManifest(ctx, ociStore, opts)
	}
	// if there is more than one manifest in the store, we are dealing with multiple artifacts, so in this case we should also copy the index
	// TODO(jakobmoellerdev): It might make sense here to split this into multiple manifests without a top level index as well.
	//  Currently the use cases are too unclear to decide here, but we can revisit this at any time and switch it quite easily.
	return proxyOCIStoreWithIndex(ociStore, opts)
}

func proxyOCIStoreWithIndex(ociStore *CloseableReadOnlyStore, opts *CopyOCILayoutWithIndexOptions) (ociImageSpecV1.Descriptor, content.ReadOnlyStorage, error) {
	indexJSON, err := json.Marshal(ociStore.Index)
	if err != nil {
		return ociImageSpecV1.Descriptor{}, nil, fmt.Errorf("failed to marshal index: %w", err)
	}
	index := content.NewDescriptorFromBytes(ociImageSpecV1.MediaTypeImageIndex, indexJSON)
	if err := opts.MutateParentFunc(&index); err != nil {
		return ociImageSpecV1.Descriptor{}, nil, fmt.Errorf("failed to mutate index descriptor before copy: %w", err)
	}

	opts.FindSuccessors = func(ctx context.Context, fetcher content.Fetcher, desc ociImageSpecV1.Descriptor) ([]ociImageSpecV1.Descriptor, error) {
		if content.Equal(desc, index) {
			return ociStore.Index.Manifests, nil
		}
		return content.Successors(ctx, ociStore, desc)
	}

	proxy := &descriptorStoreProxy{
		raw:             indexJSON,
		desc:            index,
		ReadOnlyStorage: ociStore,
	}
	return index, proxy, nil
}

func proxyOCIStoreWithManifest(ctx context.Context, ociStore *CloseableReadOnlyStore, opts *CopyOCILayoutWithIndexOptions) (ociImageSpecV1.Descriptor, content.ReadOnlyStorage, error) {
	manifestDesc := ociStore.Index.Manifests[0]
	manifestRawStream, err := ociStore.Fetch(ctx, manifestDesc)
	if err != nil {
		return ociImageSpecV1.Descriptor{}, nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	manifestRaw, err := content.ReadAll(manifestRawStream, manifestDesc)
	if err != nil {
		return ociImageSpecV1.Descriptor{}, nil, fmt.Errorf("failed to read manifest: %w", err)
	}
	var manifest ociImageSpecV1.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return ociImageSpecV1.Descriptor{}, nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}
	if err := opts.MutateParentFunc(&manifestDesc); err != nil {
		return ociImageSpecV1.Descriptor{}, nil, fmt.Errorf("failed to mutate manifest descriptor before copy: %w", err)
	}
	opts.FindSuccessors = func(ctx context.Context, fetcher content.Fetcher, desc ociImageSpecV1.Descriptor) ([]ociImageSpecV1.Descriptor, error) {
		if content.Equal(desc, manifestDesc) {
			return append([]ociImageSpecV1.Descriptor{manifest.Config}, manifest.Layers...), nil
		}
		return content.Successors(ctx, ociStore, desc)
	}
	proxy := &descriptorStoreProxy{
		raw:             manifestRaw,
		desc:            manifestDesc,
		ReadOnlyStorage: ociStore,
	}
	return manifestDesc, proxy, nil
}

type descriptorStoreProxy struct {
	raw  []byte
	desc ociImageSpecV1.Descriptor
	content.ReadOnlyStorage
}

func (p *descriptorStoreProxy) Exists(ctx context.Context, desc ociImageSpecV1.Descriptor) (bool, error) {
	if p.desc.Digest.String() == desc.Digest.String() {
		return true, nil
	}
	return p.ReadOnlyStorage.Exists(ctx, desc)
}

func (p *descriptorStoreProxy) Fetch(ctx context.Context, desc ociImageSpecV1.Descriptor) (io.ReadCloser, error) {
	if p.desc.Digest.String() == desc.Digest.String() {
		return io.NopCloser(bytes.NewReader(p.raw)), nil
	}
	return p.ReadOnlyStorage.Fetch(ctx, desc)
}

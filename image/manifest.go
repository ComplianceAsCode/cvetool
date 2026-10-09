// This is lifted from Clairctl

package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/zlog"
)

const (
	userAgent = `cvetool/1`
)

func rt(ctx context.Context, ref string) (http.RoundTripper, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	repo := r.Context()

	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return nil, err
	}
	rt := http.DefaultTransport
	rt = transport.NewUserAgent(rt, userAgent)
	rt = transport.NewRetry(rt)
	rt, err = transport.NewWithContext(ctx, repo.Registry, auth, rt, []string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, err
	}
	return rt, nil
}

// NewRegistryClient returns an authenticated client for the registry hosting ref.
func NewRegistryClient(ctx context.Context, ref string) (*http.Client, error) {
	rt, err := rt(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: rt}, nil
}

func ManifestFromRemote(ctx context.Context, cl *http.Client, r string) (*claircore.Manifest, error) {
	ref, err := name.ParseReference(r)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref, remote.WithTransport(cl.Transport))
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	dig, err := img.Digest()
	if err != nil {
		return nil, err
	}
	ccd, err := claircore.ParseDigest(dig.String())
	if err != nil {
		return nil, err
	}
	out := claircore.Manifest{Hash: ccd}
	zlog.Debug(ctx).
		Str("ref", r).
		Stringer("digest", ccd).
		Msg("found manifest")

	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Str("ref", r).
		Int("count", len(ls)).
		Msg("found layers")

	repo := ref.Context()
	rURL := url.URL{
		Scheme: repo.Scheme(),
		Host:   repo.RegistryStr(),
	}

	for _, l := range ls {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		ccd, err := claircore.ParseDigest(d.String())
		if err != nil {
			return nil, err
		}
		u, err := rURL.Parse(path.Join("/", "v2", repo.RepositoryStr(), "blobs", d.String()))
		if err != nil {
			return nil, err
		}
		out.Layers = append(out.Layers, &claircore.Layer{
			Hash: ccd,
			URI:  u.String(),
		})
	}

	return &out, nil
}

type indexFile struct {
	Manifests []manifestInfo `json:"manifests"`
}

type manifestInfo struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type manifestFile struct {
	Layers []layerInfo `json:"layers"`
}

type layerInfo struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type localArchive interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}

type localManifestReaders []io.Closer

func (r localManifestReaders) Close() error {
	return closeManifestResources(nil, r)
}

func closeManifestResources(layers []*claircore.Layer, readers []io.Closer) error {
	var errs []error
	for _, layer := range layers {
		if layer != nil {
			errs = append(errs, layer.Close())
		}
	}
	for _, reader := range readers {
		if reader != nil {
			errs = append(errs, reader.Close())
		}
	}
	return errors.Join(errs...)
}

func ManifestFromLocal(ctx context.Context, exportDir string) (*claircore.Manifest, io.Closer, error) {
	f, err := os.Open(exportDir)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open tar: %w", err)
	}
	return parseLocalArchive(ctx, f)
}

func parseLocalArchive(ctx context.Context, f localArchive) (out *claircore.Manifest, readerCloser io.Closer, err error) {
	parsed := &claircore.Manifest{}
	readers := []io.Closer{f}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeManifestResources(parsed.Layers, readers))
		}
	}()

	m := &manifestFile{}
	i := &indexFile{}
	fs, err := tarfs.New(f)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create tarfs: %w", err)
	}
	index, err := fs.Open("index.json")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open index.json: %w", err)
	}
	defer index.Close()
	b, err := io.ReadAll(index)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read index.json: %w", err)
	}
	err = json.Unmarshal(b, &i)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to unmarshal index.json: %w", err)
	}
	manifestDigest := ""
	for _, m := range i.Manifests {
		if m.MediaType == "application/vnd.oci.image.manifest.v1+json" {
			manifestDigest = m.Digest
			break
		}
	}
	if manifestDigest == "" {
		return nil, nil, fmt.Errorf("manifest digest not found")
	}
	md, err := claircore.ParseDigest(manifestDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse manifest digest: %w", err)
	}
	parsed.Hash = md

	mdb := make([]byte, hex.EncodedLen(len(md.Checksum())))
	hex.Encode(mdb, md.Checksum())
	manifestPath := filepath.Join("blobs", md.Algorithm(), string(mdb))
	manifest, err := fs.Open(manifestPath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open manifest: %w", err)
	}
	defer manifest.Close()

	b, err = io.ReadAll(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read manifest: %w", err)
	}
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	// We have to revert to tar.NewReader() because tarfs.New() doesn't support
	// seeking.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("unable to rewind tar: %w", err)
	}
	tr := tar.NewReader(f)
	parsed.Layers = make([]*claircore.Layer, len(m.Layers))
	seenLayerBlobs := make(map[string]struct{})
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read layer: %w", err)
		}
		// Reject path traversal (zip slip) entries.
		cleanName := filepath.Clean(filepath.FromSlash(hdr.Name))
		if !filepath.IsLocal(cleanName) {
			return nil, nil, fmt.Errorf("invalid tar entry path %q", hdr.Name)
		}
		start, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get layer offset: %w", err)
		}
		matchedLayerBlob := false
		for i, l := range m.Layers {
			ld, err := claircore.ParseDigest(l.Digest)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to parse layer digest: %w", err)
			}

			ldb := make([]byte, hex.EncodedLen(len(ld.Checksum())))
			hex.Encode(ldb, ld.Checksum())
			layerPath := filepath.Join("blobs", ld.Algorithm(), string(ldb))
			if cleanName == layerPath {
				if !matchedLayerBlob {
					if _, seen := seenLayerBlobs[layerPath]; seen {
						return nil, nil, fmt.Errorf("duplicate layer blob entry %q", cleanName)
					}
					seenLayerBlobs[layerPath] = struct{}{}
					matchedLayerBlob = true
				}
				ra := io.NewSectionReader(f, start, hdr.Size)
				var rAt io.ReaderAt
				switch l.MediaType {
				case "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip":
					gr, err := gzip.NewReader(ra)
					if err != nil {
						return nil, nil, fmt.Errorf("unable to create gzip reader: %w", err)
					}
					tmp, err := os.CreateTemp("", "layer-*.tar")
					if err != nil {
						return nil, nil, fmt.Errorf("unable to create temp file: %w", errors.Join(err, gr.Close()))
					}
					readers = append(readers, tmp)
					if _, err := io.Copy(tmp, gr); err != nil {
						return nil, nil, errors.Join(fmt.Errorf("unable to decompress layer: %w", err), gr.Close())
					}
					if err := gr.Close(); err != nil {
						return nil, nil, fmt.Errorf("unable to close gzip reader: %w", err)
					}
					if _, err := tmp.Seek(0, io.SeekStart); err != nil {
						return nil, nil, fmt.Errorf("unable to rewind temp file: %w", err)
					}
					os.Remove(tmp.Name())
					rAt = tmp
				case "application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar":
					// uncompressed tar, use section directly
					rAt = ra
				default:
					return nil, nil, fmt.Errorf("unsupported layer media type: %s", l.MediaType)
				}
				layer := &claircore.Layer{Hash: ld}
				err = layer.Init(ctx, &claircore.LayerDescription{
					Digest:    ld.String(),
					MediaType: l.MediaType,
				}, rAt)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to initialize layer: %w", err)
				}
				parsed.Layers[i] = layer
			}
		}
	}
	for i, l := range parsed.Layers {
		if l == nil {
			return nil, nil, fmt.Errorf("layer %d (%s) not found in tar", i, m.Layers[i].Digest)
		}
	}
	return parsed, localManifestReaders(readers), nil

}

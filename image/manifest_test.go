package image

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/quay/claircore/libindex"
	"golang.org/x/tools/txtar"
)

func TestManifestFromLocal_rejectsTarSlipPaths(t *testing.T) {
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "export.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	hdr := &tar.Header{
		Name:     "../../../outside/evil.tar",
		Mode:     0600,
		Size:     0,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = ManifestFromLocal(context.Background(), tarPath)
	if err == nil {
		t.Fatal("expected error for path traversal in tar entry name")
	}
}

// writeTarFromTxtar converts a txtar-like archive into a tar file on disk.
func writeTarFromTxtar(t *testing.T, txtarPath string) string {
	t.Helper()
	b, err := os.ReadFile(txtarPath)
	if err != nil {
		t.Fatalf("read txtar: %v", err)
	}
	ar := txtar.Parse(b)

	tmpTar := filepath.Join(t.TempDir(), "image-save.tar")
	tf, err := os.Create(tmpTar)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer tf.Close()
	tw := tar.NewWriter(tf)
	for _, fe := range ar.Files {
		if fe.Name == "" {
			t.Fatalf("empty file name in txtar")
		}
		name := fe.Name
		data := fe.Data
		if strings.HasSuffix(name, ".b64") {
			decoded, err := base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				t.Fatalf("base64 decode %s: %v", name, err)
			}
			data = decoded
			name = strings.TrimSuffix(name, ".b64")
		}

		h := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := io.Copy(tw, bytes.NewReader(data)); err != nil {
			t.Fatalf("write contents %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return tmpTar
}

func TestLocalManifest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		txtarRelPath     string
		wantManifestHash string
		wantLayerHash    string
	}{
		{
			name:             "docker save",
			txtarRelPath:     "testdata/docker_save.txtar",
			wantManifestHash: "sha256:c9b978d8d0fa53a27117f46b2e17ce906a9de863df82d7709e73868a4932f750",
			wantLayerHash:    "sha256:e7328e803158cca63d8efdbe1caefb1b51654de77e5fa8691079ad06db1abf75",
		},
		{
			name:             "podman save",
			txtarRelPath:     "testdata/podman_save.txtar",
			wantManifestHash: "sha256:869d3637f2f9b10c265e4bab4b0eccfe8770520e6e903e7dd8acf33b4987bfc1",
			wantLayerHash:    "sha256:3c6d585e6a72780f0632d16bb8bfd98dfc35b403a11f5cd61925ec31643a76d3",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exportTar := writeTarFromTxtar(t, tt.txtarRelPath)
			ctx := context.Background()
			m, err := ManifestFromLocal(ctx, exportTar)
			if err != nil {
				t.Fatalf("InspectLocal error: %v", err)
			}
			t.Cleanup(func() {
				for _, l := range m.Layers {
					if l != nil {
						_ = l.Close()
					}
				}
			})
			if m.Hash.String() != tt.wantManifestHash {
				t.Fatalf("manifest hash = %s, want %s", m.Hash.String(), tt.wantManifestHash)
			}
			if len(m.Layers) == 0 {
				t.Fatalf("no layers parsed")
			}
			found := false
			for _, l := range m.Layers {
				if l.Hash.String() == tt.wantLayerHash {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected layer hash %s not found in layers", tt.wantLayerHash)
			}
		})
	}
}

func TestRemoteManifestStableURIs(t *testing.T) {
	ctx := context.Background()

	reg := registry.New()
	var blobGets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
			blobGets.Add(1)
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	img, err := random.Image(1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	refStr := u.Host + "/test/repo:latest"
	ref, err := name.ParseReference(refStr)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	blobGets.Store(0)

	cl, err := NewRegistryClient(ctx, refStr)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := ManifestFromRemote(ctx, cl, refStr)
	if err != nil {
		t.Fatal(err)
	}
	if len(mf.Layers) != 3 {
		t.Fatalf("got %d layers, want 3", len(mf.Layers))
	}
	if got := blobGets.Load(); got != 0 {
		t.Fatalf("manifest construction fetched %d layer blobs, want 0", got)
	}
	for _, l := range mf.Layers {
		lu, err := url.Parse(l.URI)
		if err != nil {
			t.Fatal(err)
		}
		if lu.Host != u.Host {
			t.Errorf("layer URI host = %q, want %q", lu.Host, u.Host)
		}
		wantPath := "/v2/test/repo/blobs/" + l.Hash.String()
		if lu.Path != wantPath {
			t.Errorf("layer URI path = %q, want %q", lu.Path, wantPath)
		}
		if lu.RawQuery != "" {
			t.Errorf("layer URI has query %q, want none", lu.RawQuery)
		}
		if len(l.Headers) != 0 {
			t.Errorf("layer has captured headers: %v", l.Headers)
		}
	}
}

func TestRealizeThroughRedirect(t *testing.T) {
	ctx := context.Background()

	reg := registry.New()
	var registrySawAuth atomic.Bool
	var requireAuth atomic.Bool
	const wantAuth = "Basic dGVzdDp0ZXN0"
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected Authorization header", http.StatusBadRequest)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(storage.Close)

	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth.Load() && r.URL.Path != "/v2/" && r.Header.Get("Authorization") != wantAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") == wantAuth {
			registrySawAuth.Store(true)
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/sha256:") {
			http.Redirect(w, r, storage.URL+r.URL.Path, http.StatusTemporaryRedirect)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(regSrv.Close)

	u, err := url.Parse(regSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	refStr := u.Host + "/test/redirect:latest"
	ref, err := name.ParseReference(refStr)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}

	configDir := t.TempDir()
	config := fmt.Sprintf(`{"auths":{"%s":{"auth":"dGVzdDp0ZXN0"}}}`, u.Host)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DOCKER_CONFIG", configDir)
	registrySawAuth.Store(false)
	requireAuth.Store(true)

	cl, err := NewRegistryClient(ctx, refStr)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := ManifestFromRemote(ctx, cl, refStr)
	if err != nil {
		t.Fatal(err)
	}
	if !registrySawAuth.Load() {
		t.Fatal("registry did not receive configured authorization")
	}

	fa := libindex.NewRemoteFetchArena(cl, t.TempDir())
	t.Cleanup(func() { _ = fa.Close(ctx) })
	rz := fa.Realizer(ctx)
	t.Cleanup(func() { _ = rz.Close() })
	if err := rz.Realize(ctx, mf.Layers); err != nil {
		t.Fatalf("realize: %v", err)
	}
	for _, l := range mf.Layers {
		if _, err := l.Reader(); err != nil {
			t.Errorf("layer %v not realized: %v", l.Hash, err)
		}
	}
}

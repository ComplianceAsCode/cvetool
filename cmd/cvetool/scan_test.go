package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ComplianceAsCode/cvetool/datastore"
	"github.com/ComplianceAsCode/cvetool/image"
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/rhel"
)

func TestLocalOCIIndexLifecycle(t *testing.T) {
	ctx := context.Background()
	layerData := scanLayerTar(t)
	archivePath := scanOCITar(t, layerData)
	mf, readerCloser, err := image.ManifestFromLocal(ctx, archivePath)
	if err != nil {
		t.Fatalf("ManifestFromLocal: %v", err)
	}
	if len(mf.Layers) != 1 {
		t.Fatalf("ManifestFromLocal returned %d layers, want 1", len(mf.Layers))
	}

	indexAndCloseScanResources(t, mf, NewLocalFetchArena(mf.Layers, readerCloser))
}

func TestFilesystemIndexLifecycle(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("create etc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=rhel\nVERSION_ID=9\n"), 0o644); err != nil {
		t.Fatalf("write os-release: %v", err)
	}
	mf, err := image.ManifestFromFilesystem(ctx, root)
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}

	indexAndCloseScanResources(t, mf, NewLocalFetchArena(mf.Layers, nil))
}

func TestRemoteIndexLifecycle(t *testing.T) {
	layerData := scanLayerTar(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveScanLayer(w, r, layerData)
	}))
	t.Cleanup(server.Close)

	digest, err := claircore.ParseDigest(scanDigest(layerData))
	if err != nil {
		t.Fatalf("parse layer digest: %v", err)
	}
	mf := &claircore.Manifest{
		Hash: digest,
		Layers: []*claircore.Layer{{
			Hash: digest,
			URI:  server.URL,
		}},
	}
	arena := libindex.NewRemoteFetchArena(server.Client(), t.TempDir())
	indexAndCloseScanResources(t, mf, arena)
}

func TestScanCleanupBeforeRealize(t *testing.T) {
	ctx := context.Background()
	mf, err := image.ManifestFromFilesystem(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}
	if len(mf.Layers) != 1 {
		t.Fatalf("ManifestFromFilesystem returned %d layers, want 1", len(mf.Layers))
	}

	readerErr := errors.New("reader close failed")
	reader := &scanTestCloser{err: readerErr}
	tracked := newTrackingFetchArena(NewLocalFetchArena(mf.Layers, reader))
	if err := closeScanResources(ctx, nil, tracked); !errors.Is(err, readerErr) {
		t.Fatalf("tracking arena Close error = %v, want reader close error", err)
	}
	if reader.calls != 1 {
		t.Fatalf("reader closed %d times, want 1", reader.calls)
	}
	assertAlreadyClosed(t, mf.Layers[0])
}

func TestScanCleanupPreservesRealizerAndArenaErrors(t *testing.T) {
	ctx := context.Background()
	mf, err := image.ManifestFromFilesystem(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}
	layer := mf.Layers[0]
	t.Cleanup(func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Errorf("Layer.Close panicked during cleanup: %v", recovered)
			}
		}()
		if err := layer.Close(); err != nil {
			t.Errorf("Layer.Close during cleanup: %v", err)
		}
	})

	base := &fakeCloseArena{realizerErr: errRealizerClose, arenaErr: errArenaClose}
	tracked := newTrackingFetchArena(base)
	var li *libindex.Libindex
	resourcesClosed := false
	t.Cleanup(func() {
		if resourcesClosed {
			return
		}
		if li != nil {
			_ = li.Close(ctx)
		}
		_ = tracked.Close(ctx)
	})

	li, err = libindex.New(ctx, &libindex.Options{
		Store:      datastore.NewLocalIndexerStore(),
		Locker:     NewLocalLockSource(),
		Ecosystems: []*indexer.Ecosystem{rhel.NewEcosystem(ctx)},
		FetchArena: tracked,
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("libindex.New: %v", err)
	}
	if _, err := li.Index(ctx, mf); err != nil {
		t.Fatalf("Libindex.Index: %v", err)
	}

	closeErr := closeScanResources(ctx, li, tracked)
	resourcesClosed = true
	if !errors.Is(closeErr, errRealizerClose) {
		t.Fatalf("closeScanResources error = %v, want realizer close error", closeErr)
	}
	if !errors.Is(closeErr, errArenaClose) {
		t.Fatalf("closeScanResources error = %v, want arena close error", closeErr)
	}
	if base.closeCalls != 1 {
		t.Fatalf("underlying arena closed %d times, want 1", base.closeCalls)
	}
}

func TestIndexFailureCleanupPreservesCloseErrors(t *testing.T) {
	ctx := context.Background()
	mf, err := image.ManifestFromFilesystem(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}
	if len(mf.Layers) != 1 {
		t.Fatalf("ManifestFromFilesystem returned %d layers, want 1", len(mf.Layers))
	}
	layer := mf.Layers[0]
	t.Cleanup(func() {
		if err := layer.Close(); err != nil {
			t.Errorf("Layer.Close during cleanup: %v", err)
		}
	})

	realizeErr := errors.New("realize failed")
	realizerCloseErr := errors.New("realizer close failed")
	arenaCloseErr := errors.New("arena close failed")
	base := &fakeCloseArena{
		realizeErr:  realizeErr,
		realizerErr: realizerCloseErr,
		arenaErr:    arenaCloseErr,
	}
	tracked := newTrackingFetchArena(base)
	var li *libindex.Libindex
	resourcesClosed := false
	t.Cleanup(func() {
		if !resourcesClosed {
			_ = closeScanResources(ctx, li, tracked)
		}
	})

	li, err = libindex.New(ctx, &libindex.Options{
		Store:      datastore.NewLocalIndexerStore(),
		Locker:     NewLocalLockSource(),
		Ecosystems: []*indexer.Ecosystem{rhel.NewEcosystem(ctx)},
		FetchArena: tracked,
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("libindex.New: %v", err)
	}
	if _, err := li.Index(ctx, mf); !errors.Is(err, realizeErr) {
		t.Fatalf("Libindex.Index error = %v, want realize error", err)
	}

	closeErr := closeScanResources(ctx, li, tracked)
	resourcesClosed = true
	if !errors.Is(closeErr, realizerCloseErr) {
		t.Errorf("closeScanResources error = %v, want realizer close error", closeErr)
	}
	if !errors.Is(closeErr, arenaCloseErr) {
		t.Errorf("closeScanResources error = %v, want arena close error", closeErr)
	}
	if base.closeCalls != 1 {
		t.Errorf("underlying arena closed %d times, want 1", base.closeCalls)
	}
}

func indexAndCloseScanResources(t *testing.T, mf *claircore.Manifest, arena indexer.FetchArena) {
	t.Helper()
	ctx := context.Background()
	tracked := newTrackingFetchArena(arena)
	var li *libindex.Libindex
	resourcesClosed := false
	t.Cleanup(func() {
		if resourcesClosed {
			return
		}
		if li != nil {
			if err := li.Close(ctx); err != nil {
				t.Errorf("Libindex.Close: %v", err)
			}
		}
		if err := tracked.Close(ctx); err != nil {
			t.Errorf("tracking FetchArena.Close: %v", err)
		}
	})

	var err error
	li, err = libindex.New(ctx, &libindex.Options{
		Store:      datastore.NewLocalIndexerStore(),
		Locker:     NewLocalLockSource(),
		Ecosystems: []*indexer.Ecosystem{rhel.NewEcosystem(ctx)},
		FetchArena: tracked,
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("libindex.New: %v", err)
	}
	if _, err := li.Index(ctx, mf); err != nil {
		t.Fatalf("Libindex.Index: %v", err)
	}
	if err := closeScanResources(ctx, li, tracked); err != nil {
		t.Errorf("closeScanResources: %v", err)
	}
	resourcesClosed = true
}

func scanLayerTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	data := []byte("algo\n")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "algo.txt",
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write layer header: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("write layer file: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer tar: %v", err)
	}
	return buf.Bytes()
}

type scanOCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type scanOCIManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	MediaType     string              `json:"mediaType"`
	Layers        []scanOCIDescriptor `json:"layers"`
}

type scanOCIIndex struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Manifests     []scanOCIDescriptor `json:"manifests"`
}

func scanOCITar(t *testing.T, layerData []byte) string {
	t.Helper()
	layerDigest := scanDigest(layerData)
	manifestData, err := json.Marshal(scanOCIManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Layers: []scanOCIDescriptor{{
			MediaType: "application/vnd.oci.image.layer.v1.tar",
			Digest:    layerDigest,
			Size:      int64(len(layerData)),
		}},
	})
	if err != nil {
		t.Fatalf("marshal OCI manifest: %v", err)
	}
	manifestDigest := scanDigest(manifestData)
	indexData, err := json.Marshal(scanOCIIndex{
		SchemaVersion: 2,
		Manifests: []scanOCIDescriptor{{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    manifestDigest,
			Size:      int64(len(manifestData)),
		}},
	})
	if err != nil {
		t.Fatalf("marshal OCI index: %v", err)
	}

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	writeScanTarEntry(t, tw, "index.json", indexData)
	writeScanTarEntry(t, tw, "blobs/sha256/"+strings.TrimPrefix(manifestDigest, "sha256:"), manifestData)
	writeScanTarEntry(t, tw, "blobs/sha256/"+strings.TrimPrefix(layerDigest, "sha256:"), layerData)
	if err := tw.Close(); err != nil {
		t.Fatalf("close OCI archive: %v", err)
	}

	path := filepath.Join(t.TempDir(), "oci.tar")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatalf("write OCI archive: %v", err)
	}
	return path
}

func writeScanTarEntry(t *testing.T, tw *tar.Writer, name string, data []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write tar header for %s: %v", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("write tar entry %s: %v", name, err)
	}
}

func scanDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

func serveScanLayer(w http.ResponseWriter, r *http.Request, data []byte) {
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Accept-Ranges", "bytes")
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	unit, spec, ok := strings.Cut(rangeHeader, "=")
	if !ok || unit != "bytes" {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	startText, endText, ok := strings.Cut(spec, "-")
	if !ok {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 || start >= int64(len(data)) {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	end := int64(len(data) - 1)
	if endText != "" {
		end, err = strconv.ParseInt(endText, 10, 64)
		if err != nil || end < start {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if end >= int64(len(data)) {
			end = int64(len(data) - 1)
		}
	}
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(data[start : end+1])
}

type scanTestCloser struct {
	calls int
	err   error
}

func (c *scanTestCloser) Close() error {
	c.calls++
	return c.err
}

package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/ComplianceAsCode/cvetool/image"
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	errRealizerClose = errors.New("realizer close")
	errArenaClose    = errors.New("arena close")
)

func TestTrackingFetchArenaJoinsCloseErrorsAndClosesOnce(t *testing.T) {
	ctx := context.Background()
	base := &fakeCloseArena{realizerErr: errRealizerClose, arenaErr: errArenaClose}
	tracked := newTrackingFetchArena(base)
	realizer := tracked.Realizer(ctx)

	if err := realizer.Close(); !errors.Is(err, errRealizerClose) {
		t.Fatalf("Realizer.Close error = %v, want realizer close error", err)
	}

	firstCloseErr := tracked.Close(ctx)
	if !errors.Is(firstCloseErr, errArenaClose) {
		t.Fatalf("Close error = %v, want arena close error", firstCloseErr)
	}
	if !errors.Is(firstCloseErr, errRealizerClose) {
		t.Fatalf("Close error = %v, want realizer close error", firstCloseErr)
	}

	secondCloseErr := tracked.Close(ctx)
	if !errors.Is(secondCloseErr, errArenaClose) {
		t.Fatalf("repeated Close error = %v, want arena close error", secondCloseErr)
	}
	if !errors.Is(secondCloseErr, errRealizerClose) {
		t.Fatalf("repeated Close error = %v, want realizer close error", secondCloseErr)
	}
	if secondCloseErr != firstCloseErr {
		t.Fatal("repeated Close did not return the stored joined error")
	}
	if base.closeCalls != 1 {
		t.Fatalf("underlying Close called %d times, want 1", base.closeCalls)
	}
}

func TestTrackingFetchArenaCollectsConcurrentRealizerCloseErrors(t *testing.T) {
	ctx := context.Background()
	const realizerCount = 8
	realizerErrs := make([]error, realizerCount)
	for i := range realizerErrs {
		realizerErrs[i] = errors.New("realizer close " + strconv.Itoa(i))
	}
	base := &fakeCloseArena{realizerErrs: realizerErrs, arenaErr: errArenaClose}
	tracked := newTrackingFetchArena(base)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range realizerCount {
		realizer := tracked.Realizer(ctx)
		realizerErr := realizerErrs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := realizer.Close(); !errors.Is(err, realizerErr) {
				t.Errorf("Realizer.Close error = %v, want %v", err, realizerErr)
			}
		}()
	}
	close(start)
	wg.Wait()

	closeErr := tracked.Close(ctx)
	for i, realizerErr := range realizerErrs {
		if !errors.Is(closeErr, realizerErr) {
			t.Errorf("Close error = %v, want realizer close error %d (%v)", closeErr, i, realizerErr)
		}
	}
	if !errors.Is(closeErr, errArenaClose) {
		t.Errorf("Close error = %v, want arena close error", closeErr)
	}
	if base.closeCalls != 1 {
		t.Fatalf("underlying Close called %d times, want 1", base.closeCalls)
	}
}

type fakeCloseArena struct {
	realizerErr  error
	realizerErrs []error
	nextRealizer int
	realizeErr   error
	arenaErr     error
	closeCalls   int
}

func (a *fakeCloseArena) Realizer(context.Context) indexer.Realizer {
	realizerErr := a.realizerErr
	if len(a.realizerErrs) > 0 {
		realizerErr = a.realizerErrs[a.nextRealizer]
		a.nextRealizer++
	}
	return &fakeCloseRealizer{realizeErr: a.realizeErr, realizerErr: realizerErr}
}

func (a *fakeCloseArena) Close(context.Context) error {
	a.closeCalls++
	return a.arenaErr
}

type fakeCloseRealizer struct {
	realizeErr  error
	realizerErr error
}

func (r *fakeCloseRealizer) Realize(context.Context, []*claircore.Layer) error {
	return r.realizeErr
}

func (r *fakeCloseRealizer) Close() error {
	return r.realizerErr
}

func TestLocalFetchArenaTransfersLayerToRealizer(t *testing.T) {
	ctx := context.Background()
	transferred := newFilesystemLayer(t)
	pending := newFilesystemLayer(t)
	arena := NewLocalFetchArena([]*claircore.Layer{transferred, pending}, nil)
	realizer := arena.Realizer(ctx)

	if err := realizer.Realize(ctx, []*claircore.Layer{transferred}); err != nil {
		t.Fatalf("Realize: %v", err)
	}

	layerFS, err := transferred.FS()
	if err != nil {
		t.Fatalf("Layer.FS: %v", err)
	}
	contents, err := fs.ReadFile(layerFS, "marker.txt")
	if err != nil {
		t.Fatalf("read layer filesystem before realizer close: %v", err)
	}
	if got, want := string(contents), "local layer"; got != want {
		t.Fatalf("marker.txt = %q, want %q", got, want)
	}

	if err := realizer.Close(); err != nil {
		t.Fatalf("realizer.Close: %v", err)
	}
	assertAlreadyClosed(t, transferred)

	if err := arena.Close(ctx); err != nil {
		t.Fatalf("arena.Close: %v", err)
	}
	assertAlreadyClosed(t, pending)
}

func TestLocalFetchArenaClosesUntransferredLayer(t *testing.T) {
	ctx := context.Background()
	layer := newFilesystemLayer(t)
	arena := NewLocalFetchArena([]*claircore.Layer{layer}, nil)

	if err := arena.Close(ctx); err != nil {
		t.Fatalf("arena.Close: %v", err)
	}

	assertAlreadyClosed(t, layer)
}

func newFilesystemLayer(t *testing.T) *claircore.Layer {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "marker.txt"), []byte("local layer"), 0o644); err != nil {
		t.Fatalf("write marker file: %v", err)
	}

	manifest, err := image.ManifestFromFilesystem(context.Background(), root)
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}
	if len(manifest.Layers) != 1 {
		t.Fatalf("ManifestFromFilesystem returned %d layers, want 1", len(manifest.Layers))
	}
	layer := manifest.Layers[0]
	t.Cleanup(func() {
		defer func() { _ = recover() }()
		if err := layer.Close(); err != nil {
			t.Errorf("cleanup Layer.Close: %v", err)
		}
	})
	return layer
}

func assertAlreadyClosed(t *testing.T, layer *claircore.Layer) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("Layer.Close did not detect a prior close")
		}
	}()
	_ = layer.Close()
}

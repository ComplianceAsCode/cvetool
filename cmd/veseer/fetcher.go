package main

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var (
	_ indexer.FetchArena = (*LocalFetchArena)(nil)
	_ indexer.Realizer   = (*realizer)(nil)
	_ indexer.FetchArena = (*trackingFetchArena)(nil)
	_ indexer.Realizer   = (*trackingRealizer)(nil)
)

type LocalFetchArena struct {
	mu      sync.Mutex
	pending map[*claircore.Layer]struct{}
	readers io.Closer
}

type LocalFetcher struct{}

func NewLocalFetchArena(layers []*claircore.Layer, readers io.Closer) *LocalFetchArena {
	pending := make(map[*claircore.Layer]struct{}, len(layers))
	for _, layer := range layers {
		pending[layer] = struct{}{}
	}
	return &LocalFetchArena{pending: pending, readers: readers}
}

// Arena does coordination and global refcounting.
func (a *LocalFetchArena) Realizer(context.Context) indexer.Realizer {
	return &realizer{arena: a}
}

func (a *LocalFetchArena) Close(context.Context) error {
	a.mu.Lock()
	layers := make([]*claircore.Layer, 0, len(a.pending))
	for layer := range a.pending {
		layers = append(layers, layer)
	}
	a.pending = nil
	readers := a.readers
	a.readers = nil
	a.mu.Unlock()

	errs := make([]error, 0, len(layers)+1)
	for _, layer := range layers {
		errs = append(errs, layer.Close())
	}
	if readers != nil {
		errs = append(errs, readers.Close())
	}
	return errors.Join(errs...)
}

type realizer struct {
	arena  *LocalFetchArena
	mu     sync.Mutex
	layers []*claircore.Layer
}

func (r *realizer) Realize(_ context.Context, ls []*claircore.Layer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.arena.mu.Lock()
	defer r.arena.mu.Unlock()

	for _, layer := range ls {
		delete(r.arena.pending, layer)
		r.layers = append(r.layers, layer)
	}
	return nil
}

func (r *realizer) Close() error {
	r.mu.Lock()
	layers := r.layers
	r.layers = nil
	r.mu.Unlock()

	errs := make([]error, 0, len(layers))
	for _, layer := range layers {
		errs = append(errs, layer.Close())
	}
	return errors.Join(errs...)
}

type trackingFetchArena struct {
	arena          indexer.FetchArena
	mu             sync.Mutex
	realizerErrors []error
	closeOnce      sync.Once
	closeErr       error
}

func newTrackingFetchArena(arena indexer.FetchArena) *trackingFetchArena {
	return &trackingFetchArena{arena: arena}
}

func (a *trackingFetchArena) Realizer(ctx context.Context) indexer.Realizer {
	return &trackingRealizer{Realizer: a.arena.Realizer(ctx), arena: a}
}

func (a *trackingFetchArena) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		arenaErr := a.arena.Close(ctx)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.closeErr = errors.Join(append(a.realizerErrors, arenaErr)...)
	})
	return a.closeErr
}

type trackingRealizer struct {
	indexer.Realizer
	arena *trackingFetchArena
}

func (r *trackingRealizer) Close() error {
	err := r.Realizer.Close()
	if err != nil {
		r.arena.mu.Lock()
		r.arena.realizerErrors = append(r.arena.realizerErrors, err)
		r.arena.mu.Unlock()
	}
	return err
}

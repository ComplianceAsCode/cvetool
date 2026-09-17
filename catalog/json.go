package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/quay/claircore/pkg/cpe"
)

type jsonCatalog struct {
	Metadata     Metadata            `json:"metadata"`
	Repositories map[string][]string `json:"repositories"`
	Packages     map[string][]Match  `json:"packages"`
}

type jsonWriter struct {
	path string
	jsonCatalog
}

type jsonReader struct{ jsonCatalog }

var _ Writer = (*jsonWriter)(nil)
var _ Reader = (*jsonReader)(nil)

func NewJSONWriter(path string) (Writer, error) {
	if path == "" {
		return nil, fmt.Errorf("empty catalog path")
	}
	return &jsonWriter{
		path: path,
		jsonCatalog: jsonCatalog{
			Repositories: map[string][]string{},
			Packages:     map[string][]Match{},
		},
	}, nil
}

func OpenJSONReader(path string) (Reader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var catalog jsonCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}
	if catalog.Repositories == nil {
		catalog.Repositories = map[string][]string{}
	}
	if catalog.Packages == nil {
		catalog.Packages = map[string][]Match{}
	}
	return &jsonReader{catalog}, nil
}

func (w *jsonWriter) AddRepository(repository Repository) error {
	if repository.ID == "" {
		return fmt.Errorf("empty repository ID")
	}
	for _, value := range repository.CPEs {
		if _, err := cpe.Unbind(value); err != nil {
			return fmt.Errorf("invalid CPE %q: %w", value, err)
		}
		if !slices.Contains(w.Repositories[repository.ID], value) {
			w.Repositories[repository.ID] = append(w.Repositories[repository.ID], value)
		}
	}
	sort.Strings(w.Repositories[repository.ID])
	return nil
}

func (w *jsonWriter) AddPackage(pkg NEVRA, match Match) error {
	if err := validateNEVRA(pkg); err != nil {
		return err
	}
	if match.RepositoryID == "" {
		return fmt.Errorf("empty repository ID")
	}
	if _, err := cpe.Unbind(match.CPE); err != nil {
		return fmt.Errorf("invalid CPE %q: %w", match.CPE, err)
	}
	key := pkg.Key()
	if !slices.Contains(w.Packages[key], match) {
		w.Packages[key] = append(w.Packages[key], match)
	}
	return nil
}

func (w *jsonWriter) SetMetadata(metadata Metadata) error {
	w.Metadata = metadata
	return nil
}

func (w *jsonWriter) Close() error {
	data, err := json.MarshalIndent(w.jsonCatalog, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(w.path, append(data, '\n'), 0600)
}

func (r *jsonReader) Lookup(_ context.Context, pkg NEVRA) ([]Match, error) {
	matches := append([]Match(nil), r.Packages[pkg.Key()]...)
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].RepositoryID != matches[j].RepositoryID {
			return matches[i].RepositoryID < matches[j].RepositoryID
		}
		return matches[i].CPE < matches[j].CPE
	})
	return matches, nil
}

func (r *jsonReader) Metadata(_ context.Context) (Metadata, error) {
	return r.jsonCatalog.Metadata, nil
}

func (r *jsonReader) RepositoryMappingFile() (string, func(), error) {
	payload := struct {
		Data map[string]struct {
			CPEs []string `json:"cpes"`
		} `json:"data"`
	}{Data: map[string]struct {
		CPEs []string `json:"cpes"`
	}{}}
	for repositoryID, cpes := range r.Repositories {
		payload.Data[repositoryID] = struct {
			CPEs []string `json:"cpes"`
		}{CPEs: cpes}
	}
	file, err := os.CreateTemp("", "cvetool-catalog-mapping-*.json")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := json.NewEncoder(file).Encode(payload); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (r *jsonReader) Close() error { return nil }

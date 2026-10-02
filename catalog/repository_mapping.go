package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/quay/claircore/pkg/cpe"
	"io"
	"net/http"
	"os"
	"sort"
)

const defaultRepositoryMappingURL = "https://access.redhat.com/security/data/metrics/repository-to-cpe.json"

type RepositoryMapping struct {
	data   map[string][]string
	source string
}

func (m RepositoryMapping) Lookup(repositoryID string) ([]string, bool) {
	cpes, ok := m.data[repositoryID]
	return append([]string(nil), cpes...), ok
}

func (m RepositoryMapping) Validate(repositoryID string) error {
	cpes, ok := m.Lookup(repositoryID)
	if !ok {
		return fmt.Errorf("repository %q is absent from mapping", repositoryID)
	}
	if len(cpes) == 0 {
		return fmt.Errorf("repository %q has no CPEs", repositoryID)
	}
	for _, value := range cpes {
		if _, err := cpe.Unbind(value); err != nil {
			return fmt.Errorf("repository %q has invalid CPE %q: %w", repositoryID, value, err)
		}
	}
	return nil
}

func (m RepositoryMapping) Fingerprint(repositoryIDs []string) string {
	type entry struct {
		ID   string   `json:"id"`
		CPEs []string `json:"cpes"`
	}
	entries := make([]entry, 0, len(repositoryIDs))
	ids := append([]string(nil), repositoryIDs...)
	sort.Strings(ids)
	for _, id := range ids {
		cpes := append([]string(nil), m.data[id]...)
		sort.Strings(cpes)
		entries = append(entries, entry{ID: id, CPEs: cpes})
	}
	return hashJSON(entries)
}

func LoadRepositoryMapping(ctx context.Context, file, url string) (RepositoryMapping, error) {
	source := file
	if source == "" {
		source = url
	}
	if source == "" {
		source = defaultRepositoryMappingURL
	}
	var data []byte
	var err error
	if file != "" {
		data, err = os.ReadFile(file)
	} else {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if requestErr != nil {
			return RepositoryMapping{}, fmt.Errorf("create repository mapping request: %w", requestErr)
		}
		var response *http.Response
		response, err = http.DefaultClient.Do(request)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				err = fmt.Errorf("mapping URL returned %s", response.Status)
			} else {
				data, err = io.ReadAll(response.Body)
			}
		}
	}
	if err != nil {
		return RepositoryMapping{}, fmt.Errorf("read repository mapping %s: %w", source, err)
	}
	var payload struct {
		Data map[string]struct {
			CPEs []string `json:"cpes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return RepositoryMapping{}, fmt.Errorf("decode repository mapping JSON: %w", err)
	}
	mapping := RepositoryMapping{data: make(map[string][]string), source: source}
	for id, repository := range payload.Data {
		mapping.data[id] = append([]string(nil), repository.CPEs...)
	}
	return mapping, nil
}

func (m RepositoryMapping) Source() string { return m.source }

func hashJSON(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

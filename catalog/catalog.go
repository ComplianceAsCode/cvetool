package catalog

import (
	"context"
	"time"
)

type Repository struct {
	ID   string
	CPEs []string
}

type Match struct {
	RepositoryID string
	CPE          string
}

type Metadata struct {
	SchemaVersion      string
	RHELVersion        string
	Architecture       string
	RepositoryIDs      []string
	MappingSource      string
	MappingFingerprint string
	PackageFingerprint string
	GeneratedAt        time.Time
}

type Reader interface {
	Lookup(context.Context, NEVRA) ([]Match, error)
	Metadata(context.Context) (Metadata, error)
	RepositoryMappingFile() (path string, cleanup func(), err error)
	Close() error
}

type Writer interface {
	AddRepository(Repository) error
	AddPackage(NEVRA, Match) error
	SetMetadata(Metadata) error
	Close() error
}

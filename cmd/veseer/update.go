package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	ds_sqlite "github.com/ComplianceAsCode/veseer/datastore/sqlite"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel/vex"
	_ "github.com/quay/claircore/updater/defaults"
	"github.com/urfave/cli/v2"
)

const oldDatabaseThresholdDuration = 24 * time.Hour * 30

// formatDatabaseAgeThreshold returns a short phrase for CLI text derived from d (e.g. "30 days", "2 days").
func formatDatabaseAgeThreshold(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	if d%(24*time.Hour) == 0 {
		n := d / (24 * time.Hour)
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	}
	if d%time.Hour == 0 {
		n := d / time.Hour
		if n == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", n)
	}
	return d.Round(time.Second).String()
}

var allowUpdatingOldDatabaseUsage = fmt.Sprintf(
	"Allow updating a database older than %s. Updating an old database is very slow, it is suggested to delete and create anew.",
	formatDatabaseAgeThreshold(oldDatabaseThresholdDuration),
)

var updateCmd = &cli.Command{
	Name:    "update",
	Aliases: []string{"u"},
	Usage:   "update the database",
	Action:  update,
	Flags: []cli.Flag{
		&cli.PathFlag{
			Name:    "db-path",
			Value:   "",
			Usage:   "where to look for the matcher DB",
			EnvVars: []string{"DB_PATH"},
		},
		&cli.BoolFlag{
			Name:  "allow-updating-old-database",
			Usage: allowUpdatingOldDatabaseUsage,
		},
	},
}

func update(c *cli.Context) error {
	ctx := c.Context
	dbPath := c.String("db-path")
	allowUpdatingOldDatabase := c.Bool("allow-updating-old-database")
	if dbPath == "" {
		var err error
		dbPath, err = getDefaultDBPath()
		if err != nil {
			return err
		}
		if _, err := os.Stat(dbPath); err != nil {
			dbDirPath := filepath.Dir(dbPath)
			if err := os.MkdirAll(dbDirPath, 0755); err != nil {
				return fmt.Errorf("unable to create database path, %s", err)
			}
		}
	}
	matcherStore, err := ds_sqlite.NewSQLiteMatcherStore(dbPath, true)
	if err != nil {
		return fmt.Errorf("error creating sqlite backend: %v", err)
	}

	cl := &http.Client{
		Timeout: 10 * time.Minute,
	}

	matcherOpts := &libvuln.Options{
		Client:                   cl,
		Store:                    matcherStore,
		Locker:                   NewLocalLockSource(),
		DisableBackgroundUpdates: true,
		UpdateRetention:          2,
		UpdateWorkers:            1,
		// We don't need matchers for update procedure
		MatcherNames: []string{},
		// Limit CVE feed and enrichment updaters to RHEL ecosystem
		UpdaterSets: []string{"rhel-vex", "clair.cvss"},
		UpdaterConfigs: map[string]driver.ConfigUnmarshaler{
			"rhel-vex": func(v any) error {
				switch cfg := v.(type) {
				case *vex.FactoryConfig:
					cfg.CompressedFileTimeout = claircore.Duration(10 * time.Minute)
				case *vex.UpdaterConfig:
					// No additional configuration needed for individual updaters.
				default:
					return fmt.Errorf("unexpected config type: %T", v)
				}
				return nil
			},
		},
	}

	// Check last update time
	updateOps, err := matcherStore.GetUpdateOperations(ctx, driver.VulnerabilityKind)
	if err != nil {
		return fmt.Errorf("error getting update operations: %v", err)
	}

	// Find the most recent update time across all updaters
	var lastUpdate time.Time
	for _, ops := range updateOps {
		if len(ops) > 0 {
			// ops are sorted by date descending, so first element is most recent
			if ops[0].Date.After(lastUpdate) {
				lastUpdate = ops[0].Date
			}
		}
	}

	if !lastUpdate.IsZero() {
		fmt.Printf("Last update: %s (%s ago)\n", lastUpdate.Format(time.RFC1123), time.Since(lastUpdate).Round(time.Second))
		if time.Since(lastUpdate) > oldDatabaseThresholdDuration && !allowUpdatingOldDatabase {
			return fmt.Errorf(
				"Database more than %s old, refusing to update. Delete the database at %s and run this command again.",
				formatDatabaseAgeThreshold(oldDatabaseThresholdDuration),
				dbPath,
			)
		}
	} else {
		fmt.Println("No previous updates found in database")
	}

	lv, err := libvuln.New(ctx, matcherOpts)
	if err != nil {
		return fmt.Errorf("error creating Libvuln: %v", err)
	}

	if err := lv.FetchUpdates(ctx); err != nil {
		return fmt.Errorf("error updating vulnerabilities: %v", err)
	}
	if err := matcherStore.VacuumDatabase(ctx); err != nil {
		return fmt.Errorf("error vacuum database : %v", err)
	}
	return nil
}

package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/getsentry/sentry-go"
)

var (
	auth     *casbin.SyncedEnforcer
	onceAuth sync.Once
)

func Auth() *casbin.SyncedEnforcer {
	onceAuth.Do(func() {
		basePath := "casbin"

		modelFile, err := filepath.Abs(filepath.Clean(filepath.Join(basePath, "model.conf")))
		if err != nil {
			slog.Error(fmt.Sprintf("Could not read Casbin model file at %s", modelFile))
			os.Exit(1)
		}

		policyFile, err := filepath.Abs(filepath.Clean(filepath.Join(basePath, "policy.csv")))
		if err != nil {
			slog.Error(fmt.Sprintf("Could not read Casbin policy file at %s", policyFile))
			os.Exit(1)
		}

		e, err := casbin.NewSyncedEnforcer(modelFile, policyFile)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not create enforcer: %v", err))
			os.Exit(1)
		}

		if err := e.LoadPolicy(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not load policy: %v", err))
			os.Exit(1)
		}

		auth = e
	})

	return auth
}

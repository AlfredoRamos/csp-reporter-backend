package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/casbin/casbin/v2"
)

var (
	auth     *casbin.SyncedEnforcer
	onceAuth sync.Once
)

func Auth() *casbin.SyncedEnforcer {
	onceAuth.Do(func() {
		modelFile, err := filepath.Abs(filepath.Clean(filepath.Join("internal", "casbin", "model.conf")))
		if err != nil {
			//sentry.CaptureException(err)
			slog.Error(
				"Could not read Casbin model",
				slog.String("file", modelFile),
				slog.Any("error", err),
			)
			os.Exit(1)
		}

		policyFile, err := filepath.Abs(filepath.Clean(filepath.Join("internal", "casbin", "policy.csv")))
		if err != nil {
			//sentry.CaptureException(err)
			slog.Error(
				"Could not read Casbin policy",
				slog.String("file", policyFile),
				slog.Any("error", err),
			)
			os.Exit(1)
		}

		e, err := casbin.NewSyncedEnforcer(modelFile, policyFile)
		if err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not create enforcer", slog.Any("error", err))
			os.Exit(1)
		}

		if err := e.LoadPolicy(); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not load policy", slog.Any("error", err))
			os.Exit(1)
		}

		auth = e
	})

	return auth
}

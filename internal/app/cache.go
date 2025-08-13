package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"alfredoramos.mx/csp-reporter/internal/env"
	"github.com/getsentry/sentry-go"
	"github.com/valkey-io/valkey-go"
)

var (
	rdb       valkey.Client
	onceCache sync.Once
)

func Cache() valkey.Client {
	onceCache.Do(func() {
		client, err := valkey.NewClient(valkey.ClientOption{
			InitAddress: []string{fmt.Sprintf("%s:%d", env.String("CACHE_HOST", ""), env.Int("CACHE_PORT", 6379))},
			Password:    env.String("CACHE_PASS", ""),
			SelectDB:    0,
		})
		if err != nil && !errors.Is(err, valkey.Nil) {
			sentry.CaptureException(err)
			slog.Error("Could not connect to Valkey", slog.Any("error", err))
			os.Exit(1)
		}

		rdb = client
	})

	return rdb
}

package app

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"

	"alfredoramos.mx/csp-reporter/internal/env"
	"github.com/valkey-io/valkey-go"
)

var (
	rdb       valkey.Client
	onceCache sync.Once
)

func Cache() valkey.Client {
	onceCache.Do(func() {
		client, err := valkey.NewClient(valkey.ClientOption{
			InitAddress: []string{net.JoinHostPort(env.String("CACHE_HOST"), env.String("CACHE_PORT", "6379"))},
			Password:    env.String("CACHE_PASS"),
			SelectDB:    0,
		})
		if err != nil && !errors.Is(err, valkey.Nil) {
			//sentry.CaptureException(err)
			slog.Error("Could not connect to Valkey", slog.Any("error", err))
			os.Exit(1)
		}

		rdb = client
	})

	return rdb
}

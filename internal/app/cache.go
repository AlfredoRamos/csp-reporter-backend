package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/getsentry/sentry-go"
	"github.com/valkey-io/valkey-go"
)

var (
	rdb       valkey.Client
	onceCache sync.Once
)

func Cache() valkey.Client {
	onceCache.Do(func() {
		port, err := strconv.Atoi(os.Getenv("CACHE_PORT"))
		if err != nil {
			sentry.CaptureException(err)
			port = 6379
		}

		client, err := valkey.NewClient(valkey.ClientOption{
			InitAddress: []string{fmt.Sprintf("%s:%d", os.Getenv("CACHE_HOST"), port)},
			Password:    os.Getenv("CACHE_PASS"),
			SelectDB:    0,
		})
		if err != nil && !errors.Is(err, valkey.Nil) {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not connect to Valkey: %v", err))
			os.Exit(1)
		}

		rdb = client
	})

	return rdb
}

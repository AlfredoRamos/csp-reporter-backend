package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/getsentry/sentry-go"
	"github.com/redis/rueidis"
)

var (
	rdb       rueidis.Client
	onceCache sync.Once
)

func Cache() rueidis.Client {
	onceCache.Do(func() {
		port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
		if err != nil {
			sentry.CaptureException(err)
			port = 6379
		}

		client, err := rueidis.NewClient(rueidis.ClientOption{
			InitAddress: []string{fmt.Sprintf("%s:%d", os.Getenv("REDIS_HOST"), port)},
			Password:    os.Getenv("REDIS_PASS"),
			SelectDB:    0,
		})
		if err != nil && !errors.Is(err, rueidis.Nil) {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not connect to Redis: %v", err))
			os.Exit(1)
		}

		rdb = client
	})

	return rdb
}

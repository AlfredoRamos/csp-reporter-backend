package helpers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/valkey-io/valkey-go"
)

const (
	batchSize int64 = 100
)

func PurgeCachePattern(pattern string) error {
	pattern = utils.CacheKey(pattern)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cursor := uint64(0)

	for {
		select {
		case <-ctx.Done():
			slog.Warn("Cache purge timeout", slog.Any("error", ctx.Err()))
			return ctx.Err()
		default:
			// Continue
		}

		result, err := app.Cache().Do(ctx, app.Cache().B().Scan().Cursor(cursor).Match(pattern).Count(batchSize).Build()).AsScanEntry()
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(
				"Could not scan keys",
				slog.String("pattern", pattern),
				slog.Any("error", err),
			)
			return err
		}

		cursor = result.Cursor

		for i := 0; i < len(result.Elements); i += int(batchSize) {
			end := min(i+int(batchSize), len(result.Elements))
			batch := result.Elements[i:end]

			cmds := make(valkey.Commands, 0, len(batch))
			for _, key := range batch {
				cmds = append(cmds, app.Cache().B().Del().Key(key).Build())
			}

			errs := []error{}
			for _, res := range app.Cache().DoMulti(ctx, cmds...) {
				if err := res.Error(); err != nil && !errors.Is(err, valkey.Nil) {
					errs = append(errs, err)
				}
			}

			if len(errs) > 0 {
				slog.Error("Error purging cache", slog.Any("error", errors.Join(errs...)))
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

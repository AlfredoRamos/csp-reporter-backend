package helpers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"github.com/getsentry/sentry-go"
	"github.com/valkey-io/valkey-go"
)

const (
	batchSize int64 = 100
)

func PurgeCachePattern(pattern string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cursor := uint64(0)

	for {
		select {
		case <-ctx.Done():
			slog.Warn(fmt.Sprintf("Cache purge timeout: %v", ctx.Err()))
			break
		default:
			// Continue
		}

		result, err := app.Cache().Do(ctx, app.Cache().B().Scan().Cursor(cursor).Match(pattern).Count(batchSize).Build()).AsScanEntry()
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not scan pattern '%s': %v", pattern, err))
			return err
		}

		cursor = result.Cursor

		for i := 0; i < len(result.Elements); i += int(batchSize) {
			end := i + int(batchSize)

			if end > len(result.Elements) {
				end = len(result.Elements)
			}

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
				slog.Error(fmt.Sprintf("Error purging cache: %v", errors.Join(errs...)))
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

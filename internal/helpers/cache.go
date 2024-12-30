package helpers

import (
	"context"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"github.com/getsentry/sentry-go"
	"github.com/valkey-io/valkey-go"
)

const (
	batchSize int64 = 100
)

func PurgeCachePattern(pattern string) error {
	ctx := context.Background()
	cursor := uint64(0)

	for {
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

			// TODO: Show errors
			app.Cache().DoMulti(ctx, cmds...)
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

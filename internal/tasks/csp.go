package tasks

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/internal/cache"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"github.com/getsentry/sentry-go"
	"github.com/goccy/go-json"
	"github.com/hibiken/asynq"
)

const (
	TaskReportAdd string = "csp:report:add"
)

type ReportAddPayload struct {
	Data helpers.CspReport `json:"data"`
}

func NewReportAddTask(d helpers.CspReport) (*asynq.Task, error) {
	payload, err := json.Marshal(ReportAddPayload{d})
	if err != nil {
		sentry.CaptureException(err)
		return nil, err
	}

	return asynq.NewTask(TaskReportAdd, payload), nil
}

func HandleReportAddTask(ctx context.Context, t *asynq.Task) error { //nolint:unused
	p := ReportAddPayload{}
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("could not decode payload: %w: %w", err, asynq.SkipRetry)
	}

	if err := helpers.NewCspReport(p.Data); err != nil { //nolint:contextcheck
		sentry.CaptureException(err)
		return fmt.Errorf("could not add CSP report: %w: %w", err, asynq.SkipRetry)
	}

	return nil
}

func NewCspReport(d helpers.CspReport) error {
	task, err := NewReportAddTask(d)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Could not create task", slog.Any("error", err))
		return err
	}

	info, err := AsynqClient().Enqueue(task, asynq.Queue(cache.Key("default")), asynq.MaxRetry(3), asynq.ProcessIn(3*time.Second), asynq.Retention(1*time.Hour))
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Could not enqueue task", slog.Any("error", err))
		return err
	}

	slog.Info(
		"Enqueued",
		slog.String("task-id", info.ID),
		slog.String("queue", info.Queue),
	)

	return nil
}

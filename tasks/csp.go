package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/helpers"
	"github.com/getsentry/sentry-go"
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
		return fmt.Errorf("Could not decode payload: %w: %w", err, asynq.SkipRetry)
	}

	//nolint:contextcheck
	if err := helpers.NewCspReport(p.Data); err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Could not add CSP report: %w: %w", err, asynq.SkipRetry)
	}

	return nil
}

func NewCspReport(d helpers.CspReport) error {
	task, err := NewReportAddTask(d)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not create task: %v", err))
		return err
	}

	info, err := AsynqClient().Enqueue(task, asynq.MaxRetry(3), asynq.ProcessIn(3*time.Second), asynq.Retention(1*time.Hour))
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not enqueue task: %v", err))
		return err
	}

	slog.Info(fmt.Sprintf("Enqueued tasks: [%s] %s", info.ID, info.Queue))

	return nil
}

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
	TaskEmailDelivery string = "email:delivery"
)

type EmailDeliveryPayload struct {
	Options *helpers.EmailOpts `json:"options"`
	Data    map[string]any     `json:"data"`
}

func NewEmailDeliveryTask(o *helpers.EmailOpts, d map[string]any) (*asynq.Task, error) {
	payload, err := json.Marshal(&EmailDeliveryPayload{o, d})
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Could not serialize payload", slog.Any("error", err))
		return nil, err
	}

	return asynq.NewTask(cache.Key(TaskEmailDelivery), payload), nil
}

func HandleEmailDeliveryTask(ctx context.Context, t *asynq.Task) error { //nolint:unused
	p := &EmailDeliveryPayload{}
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		sentry.CaptureException(err)
		slog.Error("Could not deserialize payload", slog.Any("error", err))
		return fmt.Errorf("could not decode payload: %w: %w", err, asynq.SkipRetry)
	}

	if err := helpers.SendEmail(p.Options, p.Data); err != nil { //nolint:contextcheck
		sentry.CaptureException(err)
		return fmt.Errorf("could not deliver email: %w: %w", err, asynq.SkipRetry)
	}

	return nil
}

func NewEmail(o *helpers.EmailOpts, d map[string]any) error {
	task, err := NewEmailDeliveryTask(o, d)
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
		slog.String("queue", cache.RemoveKey(info.Queue)),
	)

	return nil
}

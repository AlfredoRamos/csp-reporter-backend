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
	TaskEmailDelivery string = "email:delivery"
)

type EmailDeliveryPayload struct {
	Source helpers.EmailOpts      `json:"source"`
	Data   map[string]interface{} `json:"data"`
}

func NewEmailDeliveryTask(s helpers.EmailOpts, d map[string]interface{}) (*asynq.Task, error) {
	payload, err := json.Marshal(EmailDeliveryPayload{s, d})
	if err != nil {
		return nil, err
	}

	return asynq.NewTask(TaskEmailDelivery, payload), nil
}

func HandleEmailDeliveryTask(ctx context.Context, t *asynq.Task) error { //nolint:unused
	p := EmailDeliveryPayload{}
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("Could not decode payload: %w: %w", err, asynq.SkipRetry)
	}

	//nolint:contextcheck
	if err := helpers.SendEmail(p.Source, p.Data); err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Could not deliver email: %w: %w", err, asynq.SkipRetry)
	}

	return nil
}

func NewEmail(s helpers.EmailOpts, d map[string]interface{}) error {
	task, err := NewEmailDeliveryTask(s, d)
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

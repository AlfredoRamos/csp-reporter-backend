package tasks

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/hibiken/asynq"
)

var (
	client          *asynq.Client
	server          *asynq.Server
	serveMux        *asynq.ServeMux
	taskManager     *asynq.PeriodicTaskManager
	onceTasks       sync.Once
	onceServer      sync.Once
	onceServeMux    sync.Once
	onceTaskManager sync.Once
)

func AsynqClient() *asynq.Client {
	onceTasks.Do(func() {
		port, err := strconv.Atoi(os.Getenv("CACHE_PORT"))
		if err != nil {
			sentry.CaptureException(err)
			port = 6379
			slog.Error(fmt.Sprintf("Invalid cache port. Falling back to %d: %v", port, err))
		}

		client = asynq.NewClient(asynq.RedisClientOpt{
			Addr:     fmt.Sprintf("%s:%d", os.Getenv("CACHE_HOST"), port),
			Password: os.Getenv("CACHE_PASS"),
			DB:       0,
		})
	})

	return client
}

func AsynqServer() *asynq.Server {
	onceServer.Do(func() {
		port, err := strconv.Atoi(os.Getenv("CACHE_PORT"))
		if err != nil {
			sentry.CaptureException(err)
			port = 6379
			slog.Error(fmt.Sprintf("Invalid cache port. Falling back to %d: %v", port, err))
		}

		server = asynq.NewServer(
			asynq.RedisClientOpt{
				Addr:     fmt.Sprintf("%s:%d", os.Getenv("CACHE_HOST"), port),
				Password: os.Getenv("CACHE_PASS"),
				DB:       0,
			},
			asynq.Config{
				Concurrency: 10,
				Queues: map[string]int{
					"critical": 6,
					"default":  3,
					"low":      1,
				},
			},
		)
	})

	return server
}

func AsynqServeMux() *asynq.ServeMux {
	onceServeMux.Do(func() {
		serveMux = asynq.NewServeMux()
		serveMux.Use(loggingMiddleware)
		serveMux.HandleFunc(TaskEmailDelivery, HandleEmailDeliveryTask)
		serveMux.HandleFunc(TaskReportAdd, HandleReportAddTask)
		serveMux.HandleFunc(TaskPurgeCachePattern, HandlePurgeCachePatternTask)
	})

	return serveMux
}

func AsynqPeriodicTaskManager() *asynq.PeriodicTaskManager {
	onceTaskManager.Do(func() {
		port, err := strconv.Atoi(os.Getenv("CACHE_PORT"))
		if err != nil {
			sentry.CaptureException(err)
			port = 6379
			slog.Error(fmt.Sprintf("Invalid cache port. Falling back to %d: %v", port, err))
		}

		taskManager, err = asynq.NewPeriodicTaskManager(asynq.PeriodicTaskManagerOpts{
			RedisConnOpt: asynq.RedisClientOpt{
				Addr:     fmt.Sprintf("%s:%d", os.Getenv("CACHE_HOST"), port),
				Password: os.Getenv("CACHE_PASS"),
				DB:       0,
			},
			PeriodicTaskConfigProvider: NewTasksFileProvider(),
			SchedulerOpts: &asynq.SchedulerOpts{
				Location: utils.DefaultLocation(),
			},
			SyncInterval: 5 * time.Minute,
		})
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not create periodic task manager: %v", err))
			os.Exit(1)
		}
	})

	return taskManager
}

func loggingMiddleware(h asynq.Handler) asynq.Handler {
	return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		start := time.Now()
		slog.Info(fmt.Sprintf("Start processing [%s]", t.Type()))

		if err := h.ProcessTask(ctx, t); err != nil {
			sentry.CaptureException(fmt.Errorf("Could not process task [%s] '%s': %w", t.Type(), t.Payload(), err))
			return err
		}

		slog.Info(fmt.Sprintf("Finished processing [%s]. Elapsed time: %v", t.Type(), time.Since(start)))
		return nil
	})
}

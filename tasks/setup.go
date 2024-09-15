package tasks

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"alfredoramos.mx/csp-reporter/utils"
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
		port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
		if err != nil {
			port = 6379
		}

		client = asynq.NewClient(asynq.RedisClientOpt{
			Addr:     fmt.Sprintf("%s:%d", os.Getenv("REDIS_HOST"), port),
			Password: os.Getenv("REDIS_PASS"),
			DB:       0,
		})

		// defer client.Close()
	})

	return client
}

func AsynqServer() *asynq.Server {
	onceServer.Do(func() {
		port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
		if err != nil {
			port = 6379
		}

		server = asynq.NewServer(
			asynq.RedisClientOpt{
				Addr:     fmt.Sprintf("%s:%d", os.Getenv("REDIS_HOST"), port),
				Password: os.Getenv("REDIS_PASS"),
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
		serveMux.HandleFunc(TaskEmailDelivery, HandleEmailDeliveryTask)
	})

	return serveMux
}

func AsynqPeriodicTaskManager() *asynq.PeriodicTaskManager {
	onceTaskManager.Do(func() {
		port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
		if err != nil {
			port = 6379
		}

		taskManager, err = asynq.NewPeriodicTaskManager(asynq.PeriodicTaskManagerOpts{
			RedisConnOpt: asynq.RedisClientOpt{
				Addr:     fmt.Sprintf("%s:%d", os.Getenv("REDIS_HOST"), port),
				Password: os.Getenv("REDIS_PASS"),
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

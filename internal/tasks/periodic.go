package tasks

import (
	"log/slog"
	"os"
	"path/filepath"

	"alfredoramos.mx/csp-reporter/internal/cache"
	"github.com/goccy/go-yaml"
	"github.com/hibiken/asynq"
)

type FileBasedConfigProvider struct {
	Filename string
}

type TasksConfig struct {
	Cronspec string `yaml:"cronspec"`
	TaskType string `yaml:"task_type"`
	Queue    string `yaml:"queue"`
}

type PeriodicTaskConfigContainer struct {
	Configs []*TasksConfig `yaml:"configs"`
}

func NewTasksFileProvider() *FileBasedConfigProvider {
	configFile, err := filepath.Abs(filepath.Clean(filepath.Join("internal", "tasks", "config.yml")))
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not read tasks config", slog.String("file", configFile))
		return &FileBasedConfigProvider{}
	}

	return &FileBasedConfigProvider{
		Filename: configFile,
	}
}

func (p *FileBasedConfigProvider) GetConfigs() ([]*asynq.PeriodicTaskConfig, error) {
	data, err := os.ReadFile(p.Filename)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not read tasks config file", slog.Any("error", err))
		return nil, err
	}

	c := PeriodicTaskConfigContainer{}
	if err := yaml.Unmarshal(data, &c); err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not parse tasks config file", slog.Any("error", err))
		return nil, err
	}

	configs := []*asynq.PeriodicTaskConfig{}

	for _, cfg := range c.Configs {
		opts := make([]asynq.Option, 0, 2)
		opts = append(opts, asynq.MaxRetry(3))

		if len(cfg.Queue) < 1 {
			cfg.Queue = "default"
		}

		opts = append(opts, asynq.Queue(cache.Key(cfg.Queue)))

		configs = append(configs, &asynq.PeriodicTaskConfig{
			Cronspec: cfg.Cronspec,
			Task:     asynq.NewTask(cache.Key(cfg.TaskType), nil, opts...),
			Opts:     opts,
		})
	}

	return configs, nil
}

package tasks

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/hibiken/asynq"
	"gopkg.in/yaml.v3"
)

type FileBasedConfigProvider struct {
	Filename string
}

type TasksConfig struct {
	Cronspec string `yaml:"cronspec"`
	TaskType string `yaml:"task_type"`
}

type PeriodicTaskConfigContainer struct {
	Configs []*TasksConfig `yaml:"configs"`
}

func NewTasksFileProvider() *FileBasedConfigProvider {
	configFile, err := filepath.Abs(filepath.Clean(filepath.Join("tasks", "config.yml")))
	if err != nil {
		slog.Error(fmt.Sprintf("Could not read tasks config file at %s", configFile))
		return &FileBasedConfigProvider{}
	}

	return &FileBasedConfigProvider{
		Filename: configFile,
	}
}

func (p *FileBasedConfigProvider) GetConfigs() ([]*asynq.PeriodicTaskConfig, error) {
	data, err := os.ReadFile(p.Filename)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not read tasks config file: %v", err))
		return nil, err
	}

	c := &PeriodicTaskConfigContainer{}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}

	configs := []*asynq.PeriodicTaskConfig{}

	for _, cfg := range c.Configs {
		configs = append(configs, &asynq.PeriodicTaskConfig{
			Cronspec: cfg.Cronspec,
			Task:     asynq.NewTask(cfg.TaskType, nil),
		})
	}

	return configs, nil
}

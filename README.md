# About

Backend for the **CSP Reporter** REST API using [Fiber](https://gofiber.io), [GORM](https://gorm.io), [Asynq](https://github.com/hibiken/asynq) and [Sentry](https://github.com/getsentry/sentry-go).

[![Build Status - Main branch](https://img.shields.io/github/actions/workflow/status/AlfredoRamos/csp-reporter-backend/ci.yml?branch=main&style=flat-square&label=main)](https://github.com/AlfredoRamos/csp-reporter-backend/actions/workflows/ci.yml)
[![Build Status - Dev branch](https://img.shields.io/github/actions/workflow/status/AlfredoRamos/csp-reporter-backend/ci.yml?branch=dev&style=flat-square&label=dev)](https://github.com/AlfredoRamos/csp-reporter-backend/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/github/v/tag/AlfredoRamos/csp-reporter-backend?sort=semver&style=flat-square&label=stable)](https://github.com/AlfredoRamos/csp-reporter-backend/tags)

# Setup

## Requirements

- [Go](https://go.dev/dl/) >= 1.26.0
- [PostgreSQL](https://www.postgresql.org/download/) >= 17.2
- [Valkey](https://valkey.io/download/) >= 8.1

### VSCode extensions

- [Go](https://marketplace.visualstudio.com/items?itemName=golang.Go)
- [EditorConfig for VS Code](https://marketplace.visualstudio.com/items?itemName=EditorConfig.EditorConfig)
- [Even Better TOML](https://marketplace.visualstudio.com/items?itemName=tamasfe.even-better-toml)
- [Prettier - Code formatter](https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode)
- [Markdown All in One](https://marketplace.visualstudio.com/items?itemName=yzhang.markdown-all-in-one)
- [Rainbow CSV](https://marketplace.visualstudio.com/items?itemName=mechatroner.rainbow-csv)

## Install dependencies

```shell
go mod tidy
```

## Setup live-reload

```shell
go install github.com/air-verse/air@latest
```

## Setup environment helper

```shell
go install github.com/joho/godotenv/cmd/godotenv@latest
```

## Setup linters

```shell
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install golang.org/x/tools/cmd/deadcode@latest
go install golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest
```

## Generate key pairs

```shell
make keys
```

# Build application

## Production

```shell
make build
```

## Development

```shell
air
```

### Linters

```shell
make lint
```

## Cache

### Enter CLI

```shell
valkey-cli
```

### List all revoked access tokens

```shell
SMEMBERS access-tokens:revoked
```

### Manually add revoked access token

```shell
SADD access-tokens:revoked "<JTI>"
```

### Manually remove revoked access token

```shell
SREM access-tokens:revoked "<JTI>"
```

For more information, refer to the official documentation for sets:

- [Valkey sets](https://valkey.io/topics/sets/)
- [Valkey sets: Commands](https://valkey.io/commands/#set)

## Queue

### Monitoring

#### Web

Download latest version from [releases](https://github.com/hibiken/asynq/releases).

```shell
./asynqmon --max-payload-length 5000
```

#### Command line

```shell
go install github.com/hibiken/asynq/tools/asynq@latest
asynq dash
```

# Translate

## Setup

```shell
go install github.com/nicksnyder/go-i18n/v2/goi18n@latest
```

## Extract messages

```shell
make i18n-extract
```

## Update translations

```shell
make i18n-update
```

## Finish translations

```shell
make i18n-finish
```

## Create new language

```shell
make lang=<lang> i18n-new
```

# Documentation

## setup

```shell
go install github.com/swaggo/swag/v2/cmd/swag@latest
```

## Build documentation

```shell
make docs
```

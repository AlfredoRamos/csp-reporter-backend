# About

Backend for the **CSP Reporter** REST API using [Fiber](https://gofiber.io), [GORM](https://gorm.io), [Asynq](https://github.com/hibiken/asynq) and [Sentry](https://github.com/getsentry/sentry-go).

[![Build Status - Main branch](https://img.shields.io/github/actions/workflow/status/AlfredoRamos/csp-reporter-backend/ci.yml?branch=main&style=flat-square&label=main)](https://github.com/AlfredoRamos/csp-reporter-backend/actions/workflows/ci.yml)
[![Build Status - Dev branch](https://img.shields.io/github/actions/workflow/status/AlfredoRamos/csp-reporter-backend/ci.yml?branch=dev&style=flat-square&label=dev)](https://github.com/AlfredoRamos/csp-reporter-backend/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/github/v/tag/AlfredoRamos/csp-reporter-backend?sort=semver&style=flat-square&label=stable)](https://github.com/AlfredoRamos/csp-reporter-backend/tags)

# Setup

## Requirements

- [Go](https://go.dev/dl/) >= 1.24.4
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

## Setup linters

```shell
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install golang.org/x/tools/cmd/deadcode@latest
```

## Generate key pairs

```shell
mkdir -p internal/keys
go install github.com/go-jose/go-jose/v4/jose-util@latest
```

### Sign (JWS)

```shell
(cd internal/keys && jose-util generate-key --use sig --alg EdDSA && mv jwk-sig-*-priv.json signing-private.json && mv jwk-sig-*-pub.json signing-public.json)
```

### Encrypt (JWE)

```shell
(cd internal/keys && jose-util generate-key --use enc --alg ECDH-ES+A256KW && mv jwk-enc-*-priv.json encryption-private.json && mv jwk-enc-*-pub.json encryption-public.json)
```

## Email (DKIM)

```shell
openssl genrsa -traditional -out internal/keys/dkim.key 2048
openssl ec -in internal/keys/dkim.key -pubout -outform der | openssl base64 -A > internal/keys/dkim.pub
```

# Run app

## Production

```shell
go build -ldflags='-s -w' -a -installsuffix cgo -o ./bin/csp-reporter ./cmd/api/...
chmod +x csp-reporter
csp-reporter
```

## Development

```shell
air
```

### Linters

```shell
golangci-lint run ./...
govulncheck -show=traces ./...
deadcode -test ./...
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
goi18n extract -sourceLanguage=en -outdir internal/i18n -format toml
```

## Update translations

```shell
goi18n merge -outdir internal/i18n internal/i18n/active.*.toml
goi18n merge -outdir internal/i18n internal/i18n/active.*.toml internal/i18n/translate.*.toml
rm internal/i18n/translate.*.toml
```

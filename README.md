# About

Backend for the **CSP Reporter** REST API using [Fiber](https://gofiber.io), [GORM](https://gorm.io), [Asynq](https://github.com/hibiken/asynq) and [Sentry](https://github.com/getsentry/sentry-go).

# Setup

## Requirements

- [Go](https://go.dev/dl/) >= 1.23.1
- [PostgreSQL](https://www.postgresql.org/download/) >= 16.3
- [Redis](https://redis.io/download/) >= 7.2

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
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install golang.org/x/tools/cmd/deadcode@latest
```

## Generate key pairs

```shell
mkdir -p keys
go install github.com/go-jose/go-jose/v4/jose-util@latest
```

### Sign (JWS)

```shell
(cd keys && jose-util generate-key --use sig --alg EdDSA && mv jwk-sig-*-priv.json signing-private.json && mv jwk-sig-*-pub.json signing-public.json)
```

### Encrypt (JWE)

```shell
(cd keys && jose-util generate-key --use enc --alg ECDH-ES+A256KW && mv jwk-enc-*-priv.json encryption-private.json && mv jwk-enc-*-pub.json encryption-public.json)
```

# Run app

## Production

```shell
go build -ldflags='-s -w' -a -installsuffix cgo -o ./bin/csp-reporter .
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

## Redis

### Enter CLI

```shell
redis-cli
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

- [Redis sets](https://redis.io/docs/data-types/sets/)
- [Redis sets: Commands](https://redis.io/commands/?group=set)

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
goi18n extract -sourceLanguage=en -outdir i18n -format toml
```

## Update translations

```shell
goi18n merge -outdir i18n i18n/active.*.toml
goi18n merge -outdir i18n i18n/active.*.toml i18n/translate.*.toml
rm i18n/translate.*.toml
```

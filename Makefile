binary_file::=./tmp/csp-reporter
module_path::=./cmd/api/...
module_name::=$(shell sed -n 's/^module //p' go.mod)
git_version::=$(shell git describe --long --tags 2>/dev/null)
app_version::=$(shell if [ -n "${git_version}" ]; then echo "${git_version}" | sed -E 's/([^-]*)-g([0-9a-f]+)/\1+\2/'; else printf '0.0.0-%s+%s' "$(shell git rev-list --count HEAD)" "$(shell git rev-parse --short HEAD)"; fi)
keys_path::=internal/keys
i18n_path::=internal/i18n
docker_image::=alfredoramos/csp-reporter-backend:latest

.PHONY: help deps utils build i18n-extract i18n-new i18n-update i18n-finish install keys clean docker-build docker-push

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## deps: install dependencies
deps:
	go mod tidy
	mkdir -p "$(shell dirname ${binary_file})"

## utils: install utils for subcommands
utils:
	go install github.com/nicksnyder/go-i18n/v2/goi18n@latest
	go install github.com/go-jose/go-jose/v4/jose-util@latest

## build: build the application for production
build: deps
	CGO_ENABLED=0 go build -ldflags="-s -w -X '${module_name}/internal/app.version=${app_version}'" -trimpath -a -installsuffix cgo -o "${binary_file}" "${module_path}"

## i18n-extract: extract translations
i18n-extract:
	goi18n extract -sourceLanguage=en -outdir "${i18n_path}" -format toml

lang ?=
## i18n-new: create new translation
i18n-new:
ifeq ($(strip $(lang)),)
	@echo 'Usage:'
	@echo "make lang=<lang> ${@}"
	@exit 1
endif
	touch "${i18n_path}"/translate."${lang}".toml

## i18n-update: update unfinished translation files
i18n-update:
	goi18n merge -sourceLanguage=en -outdir "${i18n_path}" "${i18n_path}"/active.*.toml

## i18n-finish: finish translation files for production
i18n-finish:
	goi18n merge -sourceLanguage=en -outdir "${i18n_path}" "${i18n_path}"/active.*.toml "${i18n_path}"/translate.*.toml
	rm "${i18n_path}"/translate.*.toml

DESTDIR ?= ./bin
## install: install the application
install:
	install -Dsm755 "${binary_file}" "$(shell realpath $(DESTDIR))/$(shell basename ${binary_file})"

## keys: generate encryption and signing keys for JWT (JWS + JWE)
keys:
	mkdir -p "${keys_path}"
	(cd "${keys_path}" && jose-util generate-key --use sig --alg EdDSA && mv -f jwk-sig-*-priv.json signing-private.json && mv -f jwk-sig-*-pub.json signing-public.json)
	(cd "${keys_path}" && jose-util generate-key --use enc --alg ECDH-ES+A256KW && mv -f jwk-enc-*-priv.json encryption-private.json && mv -f jwk-enc-*-pub.json encryption-public.json)
	openssl genrsa -traditional -out "${keys_path}"/dkim.key 2048
	openssl ec -in "${keys_path}"/dkim.key -pubout -outform der | openssl base64 -A > "${keys_path}"/dkim.pub
	chmod 644 "${keys_path}"/*.json

## clean: cleanup tasks
clean:
	rm -fR "$(shell dirname ${binary_file})"

## docker-build: build Docker image
docker-build:
	sudo docker buildx build --compress --pull --tag "${docker_image}" .

## docker-push: publish Docker image
docker-push:
	sudo docker image push "${docker_image}"

binary_file=./tmp/csp-reporter
module_path=./cmd/api/...
module_name="$$(sed -n 's/^module //p' go.mod)"
app_version="$$(git_output=$$(git describe --long --tags 2>/dev/null); if [ $${?} -eq 0 ]; then printf '%s' "$${git_output}" | sed -r 's/([^-]*-g)/r\1/;s/-/./g'; else printf '0.0.0+r%s.%s' "$$(git rev-list --count HEAD)" "$$(git rev-parse --short HEAD)"; fi)"
keys_path=internal/keys

.PHONY: help deps build install keys clean

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## deps: install dependencies
deps:
	go mod tidy
	mkdir -p "$$(dirname ${binary_file})"

## build: build the application for production
build: deps
	go env -w CGO_ENABLED=0
	go build -ldflags="-s -w -X '${module_name}/internal/app.version=${app_version}'" -trimpath -a -installsuffix cgo -o "${binary_file}" "${module_path}"

DESTDIR ?= ./bin
## install: install the application
install:
	install -Dsm755 "${binary_file}" "$$(realpath $(DESTDIR))/$$(basename ${binary_file})"

## keys: generate encryption and signing keys for JWT (JWS + JWE)
keys:
	mkdir -p "${keys_path}"
	go install github.com/go-jose/go-jose/v4/jose-util@latest
	(cd "${keys_path}" && jose-util generate-key --use sig --alg EdDSA && mv -f jwk-sig-*-priv.json signing-private.json && mv -f jwk-sig-*-pub.json signing-public.json)
	(cd "${keys_path}" && jose-util generate-key --use enc --alg ECDH-ES+A256KW && mv -f jwk-enc-*-priv.json encryption-private.json && mv -f jwk-enc-*-pub.json encryption-public.json)
	openssl genrsa -traditional -out "${keys_path}"/dkim.key 2048
	openssl ec -in "${keys_path}"/dkim.key -pubout -outform der | openssl base64 -A > "${keys_path}"/dkim.pub

## clean: cleanup tasks
clean:
	rm -fR "$$(dirname ${binary_file})"
	go clean -cache -testcache -modcache

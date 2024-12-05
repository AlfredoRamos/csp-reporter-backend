binary_file=./tmp/csp-reporter
module_path=./cmd/api/...
module_name=$$(sed -n 's/^module //p' go.mod)
app_version=$$(set -o pipefail; git describe --long --tags 2>/dev/null | sed -r 's/([^-]*-g)/r\1/;s/-/./g' || printf "r%s.%s" "$$(git rev-list --count HEAD)" "$$(git rev-parse --short HEAD)")

.PHONY: help deps build clean

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
	go build -ldflags="-s -w -X '${module_name}/app.version=${app_version}'" -a -installsuffix cgo -o "${binary_file}" "${module_path}"

DESTDIR ?= ./bin
## install: install the binary file
install:
	install -Dsm755 "${binary_file}" "$$(realpath $(DESTDIR))/$$(basename ${binary_file})"

## clean: cleanup tasks
clean:
	rm -fR "$$(dirname ${binary_file})"
	go clean -cache

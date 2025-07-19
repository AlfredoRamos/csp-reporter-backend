# ---[ Arguments ]---
ARG ALPINE_VERSION=3.22
ARG GO_VERSION=1.24-alpine

# ---[ Backend ]---
FROM golang:${GO_VERSION} AS backend-build
LABEL org.opencontainers.image.authors="Alfredo Ramos <alfredoramos@duck.com>"

# Backend setup
RUN apk upgrade --no-cache && apk add --no-cache --virtual .build-backend make git postgresql-dev
WORKDIR /srv/http/backend
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/ go env -w GOCACHE=/.cache/go-build && go mod tidy
COPY ./ ./
RUN --mount=type=cache,target=/go/pkg/mod/ --mount=type=cache,target="/.cache/go-build" make build && make DESTDIR=/usr/local install && chmod a+x /usr/local/bin/csp-reporter; \
	go install github.com/hibiken/asynq/tools/asynq@latest; \
	apk del .build-backend; \
	rm -fR .git

# ---[ Application ]---
FROM alpine:${ALPINE_VERSION}
LABEL org.opencontainers.image.authors="Alfredo Ramos <alfredoramos@duck.com>"

# Install OS dependencies
RUN apk upgrade --no-cache && apk add --no-cache tzdata curl

# App setup
WORKDIR /srv/http/backend
RUN adduser -D -H -g http http
COPY --from=backend-build /srv/http/backend/.env ./
COPY --from=backend-build /usr/local/bin/csp-reporter /go/bin/asynq /usr/local/bin/
COPY --from=backend-build /srv/http/backend/internal/keys/ internal/keys/
COPY --from=backend-build /srv/http/backend/internal/casbin/ internal/casbin/
COPY --from=backend-build /srv/http/backend/internal/templates/ internal/templates/
COPY --from=backend-build /srv/http/backend/internal/tasks/config.yml internal/tasks/

# Filesystem setup
RUN chown -R http:http -- internal/tasks/config.yml && \
	chmod 644 internal/keys/*.json

# Non-root user
USER http

# Start server
CMD ["csp-reporter"]

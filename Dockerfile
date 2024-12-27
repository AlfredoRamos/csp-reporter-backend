# ---[ Arguments ]---
ARG ALPINE_VERSION=3.21
ARG GO_VERSION=1.23-alpine

# ---[ Backend ]---
FROM golang:${GO_VERSION} AS backend-build
LABEL org.opencontainers.image.authors="Alfredo Ramos <alfredoramos@duck.com>"

# Backend setup
RUN apk upgrade --no-cache && apk add --no-cache --virtual .build-backend make git postgresql-dev
WORKDIR /srv/http/backend
RUN rm -fR tmp
COPY go.mod go.sum ./
RUN go mod tidy
COPY ./ ./
RUN make build && make DESTDIR=/usr/local/bin install && chmod a+x /usr/local/bin/csp-reporter; \
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

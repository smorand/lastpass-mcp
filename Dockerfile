ARG GO_VERSION=1.26
ARG GO_BIN
ARG HAS_INTERNAL=no
ARG HAS_DATA=no

# --- Base image with user setup ---
FROM golang:${GO_VERSION}-alpine AS prebuild

ENV USER=appuser
ENV UID=10001

RUN apk update && apk add --no-cache git ca-certificates \
    && adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# --- Conditional internal/ directory ---
FROM prebuild AS build_yes
ONBUILD COPY internal/ /build/internal

FROM prebuild AS build_no
ONBUILD RUN mkdir -p /build/internal

# --- Build stage ---
FROM build_${HAS_INTERNAL} AS build
ARG GO_BIN
COPY go.mod go.sum /build/
COPY cmd/ /build/cmd/
WORKDIR /build
RUN go mod download
RUN go mod verify
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -ldflags="-w -s" -o /go/bin/app ./cmd/${GO_BIN}

# --- Conditional data/ directory ---
FROM build AS data_yes
ONBUILD COPY data/ /data

FROM build AS data_no
ONBUILD RUN mkdir -p /data

FROM data_${HAS_DATA} AS runner

# --- Final minimal image ---
FROM scratch

COPY --from=runner /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=runner /etc/passwd /etc/group /etc/
COPY --from=runner /go/bin/app /go/bin/app
COPY --from=runner /data /data

USER appuser:appuser

EXPOSE 8080

ENTRYPOINT ["/go/bin/app"]

FROM golang:1.21-bullseye AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/generate ./cmd/generate

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl inotify-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /out/server /app/bin/server
COPY --from=builder /out/generate /app/bin/generate
ENV PATH="/app/bin:${PATH}"
ENTRYPOINT ["/app/bin/server"]

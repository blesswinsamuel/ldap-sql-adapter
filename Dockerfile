FROM golang:1.20-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -o /app/api-forward-auth ./cmd/api-forward-auth

FROM alpine:3.17

WORKDIR /app
COPY --from=builder /app/api-forward-auth ./
ENTRYPOINT ["/app/api-forward-auth"]

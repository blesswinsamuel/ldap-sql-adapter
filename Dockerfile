FROM golang:1.18-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY internal ./internal
COPY cmd ./cmd

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /app/api-forward-auth ./cmd/api-forward-auth

FROM alpine:3.12

WORKDIR /app
COPY --from=build /app/api-forward-auth /app/.env ./
ENTRYPOINT ["/app/api-forward-auth"]

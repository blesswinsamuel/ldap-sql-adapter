FROM golang:1.20-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -o /app/ldap-sql-adapter ./cmd/ldap-sql-adapter

FROM alpine:3.17

WORKDIR /app
COPY --from=builder /app/ldap-sql-adapter ./
ENTRYPOINT ["/app/ldap-sql-adapter"]

FROM golang:1.26.2-alpine3.21 AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/authpilot ./server/cmd/authpilot

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /out/authpilot /app/authpilot
COPY --from=builder /src/server/web/static /app/server/web/static

EXPOSE 8025 8026
ENTRYPOINT ["/app/authpilot"]

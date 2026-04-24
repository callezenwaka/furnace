FROM golang:1.26.2-alpine3.23 AS builder

# Upgrade Alpine packages to clear known CVEs in the builder layer.
# The final image is chainguard/static and carries none of these packages.
RUN apk upgrade --no-cache

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/furnace ./server/cmd/furnace

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /out/furnace /app/furnace
COPY --from=builder /src/server/web/static /app/server/web/static

EXPOSE 8025 8026
ENTRYPOINT ["/app/furnace"]

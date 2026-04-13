FROM golang:1.26.2-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY api/ api/
COPY internal/ internal/
COPY cmd/ cmd/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o manager ./cmd/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
ENTRYPOINT ["/manager"]

# Stage 1: Build
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X 'github.com/block/codecrucible/internal/cli.version=${VERSION}' \
              -X 'github.com/block/codecrucible/internal/cli.commit=${COMMIT}' \
              -X 'github.com/block/codecrucible/internal/cli.date=${DATE}'" \
    -o codecrucible ./cmd/codecrucible

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/codecrucible /usr/local/bin/codecrucible
COPY --from=builder /build/prompts /prompts

ENTRYPOINT ["codecrucible"]
CMD ["scan", "--prompts-dir", "/prompts/default"]

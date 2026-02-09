# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o /backfill ./cmd/backfill

# Test stage — run with: docker build --target test
FROM builder AS test
RUN go test ./... -v

# Runtime stage
FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /server /server
COPY --from=builder /backfill /backfill
EXPOSE 8080
ENTRYPOINT ["/server"]


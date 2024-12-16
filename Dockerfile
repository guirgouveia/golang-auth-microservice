# -------------------------------------------------------------------
# STAGE 1: Builder
# -------------------------------------------------------------------
FROM golang:alpine3.21 AS builder

ENV CGO_ENABLED=0
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /app/main ./cmd/app

# -------------------------------------------------------------------
# STAGE 2: Security Scan
# -------------------------------------------------------------------
FROM aquasec/trivy:latest AS scan
COPY --from=builder /app /app
RUN trivy filesystem --no-progress --exit-code 1 --severity HIGH,CRITICAL /app

# -------------------------------------------------------------------
# STAGE 3: Distroless Final
# -------------------------------------------------------------------
FROM --platform=${TARGETPLATFORM} gcr.io/distroless/static:nonroot AS final

WORKDIR /app
COPY --from=builder /app/main /app/main

USER nonroot:nonroot

EXPOSE 8080
ENTRYPOINT ["/app/main"]
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
    # STAGE 2: Distroless Final
    # -------------------------------------------------------------------
    FROM --platform=${TARGETPLATFORM} gcr.io/distroless/static:nonroot AS final
    
    # If your app needs CA certificates, use distroless/base instead or embed them in your Go binary:
    #   FROM gcr.io/distroless/base:nonroot
    #   (Which includes some certs under /etc/ssl/certs)
    
    WORKDIR /app
    COPY --from=builder /app/main /app/main

    USER nonroot:nonroot
    
    # The distroless:nonroot base defaults to non-root user
    EXPOSE 8080
    ENTRYPOINT ["/app/main"]
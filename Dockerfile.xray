FROM --platform=$BUILDPLATFORM golang:1.25.7-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk update && apk add --no-cache make

WORKDIR /src

COPY go* .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make NAME=main build
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make install_xray

FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/PasarGuard/node"

WORKDIR /app
COPY --from=builder /src /app
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray

ENTRYPOINT ["./main"]
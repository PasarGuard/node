FROM golang:1.25.1 as base

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

FROM base as builder
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o main -ldflags="-w -s" .

FROM alpine:latest

RUN apk update && apk add --no-cache make

RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/main .
COPY Makefile .

RUN make install_xray

ENTRYPOINT ["./main"]

FROM golang:1.24.0 as builder

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

COPY . .
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

ENTRYPOINT ["./main", "serve"]

FROM golang:1.23.2 as builder

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

RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/main .

RUN apk update \
    && apk add --no-cache curl bash \
    && bash -c "$(curl -L https://github.com/Gozargah/Marzban-scripts/raw/master/install_latest_xray.sh)"

ENTRYPOINT ["./main", "serve"]

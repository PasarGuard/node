FROM golang:1.23 as builder

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build -o main .

FROM ubuntu:latest

RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/main .

RUN apt-get update \
    && apt-get install -y curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && bash -c "$(curl -L https://github.com/Gozargah/Marzban-scripts/raw/master/install_latest_xray.sh)"

ENTRYPOINT ["./main", "serve"]

FROM alpine:latest

RUN apk add --no-cache git make musl-dev go

RUN mkdir /app
COPY *.go /app
COPY go.* /app

WORKDIR /app

RUN go build -o traefik-proxy-bouncer

RUN ls /app

EXPOSE 8090

ENTRYPOINT /app/traefik-proxy-bouncer
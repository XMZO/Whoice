FROM golang:1.26-alpine AS build

WORKDIR /src
COPY services/lookup-api/go.mod services/lookup-api/go.sum* ./services/lookup-api/
WORKDIR /src/services/lookup-api
RUN go mod download

WORKDIR /src
COPY services/lookup-api ./services/lookup-api
WORKDIR /src/services/lookup-api
RUN CGO_ENABLED=0 go build -o /out/whoice-api ./cmd/whoice-api

FROM alpine:3.22

RUN apk add --no-cache su-exec \
  && adduser -D -H whoice \
  && mkdir -p /data \
  && chown whoice:whoice /data
WORKDIR /app
COPY --from=build /out/whoice-api /app/whoice-api
COPY services/lookup-api/docker-entrypoint.sh /usr/local/bin/whoice-entrypoint
RUN chmod +x /usr/local/bin/whoice-entrypoint

ENV WHOICE_CONFIG=/data/whoice.toml
EXPOSE 8080

ENTRYPOINT ["whoice-entrypoint"]
CMD ["/app/whoice-api"]

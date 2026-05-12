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

RUN adduser -D -H whoice
USER whoice
WORKDIR /app
COPY --from=build /out/whoice-api /app/whoice-api

ENV WHOICE_API_ADDR=:8080
EXPOSE 8080

CMD ["/app/whoice-api"]


FROM golang:1.26-alpine AS build

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o issuer ./cmd/issuer

RUN chmod 755 issuer

FROM alpine:3.23.5

WORKDIR /app

COPY --from=build /app/issuer .

CMD ["/app/issuer"]
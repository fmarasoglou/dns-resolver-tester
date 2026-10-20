# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/dnsresolvertest .

FROM alpine:3.21 AS runtime
COPY --from=build /out/dnsresolvertest /usr/local/bin/dnsresolvertest
ENTRYPOINT ["dnsresolvertest"]

FROM golang:1.23-alpine AS test
WORKDIR /src
COPY . .
CMD ["go", "test", "-v", "./..."]

FROM golang:1.22-bookworm AS build

WORKDIR /src
COPY cmd/honeypot/go.mod ./
COPY cmd/honeypot ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/honeypot .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/honeypot /honeypot

USER nonroot:nonroot
ENTRYPOINT ["/honeypot"]

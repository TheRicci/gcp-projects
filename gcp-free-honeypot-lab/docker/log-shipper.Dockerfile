FROM golang:1.22-bookworm AS build

WORKDIR /src
COPY cmd/log-shipper/go.mod cmd/log-shipper/go.sum* ./
RUN go mod download

COPY cmd/log-shipper ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/log-shipper .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/log-shipper /log-shipper

USER nonroot:nonroot
ENTRYPOINT ["/log-shipper"]

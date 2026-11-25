# Modigliani Server: a static Go binary on a distroless base.
# Build: docker build -t modigliani-server server/
# Run:   docker run --network host -v $PWD/profiles:/profiles:ro -v $PWD/config:/config:ro \
#          -v modigliani-data:/data -v $PWD/ca:/ca:ro modigliani-server
FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/modigliani-server ./cmd/modigliani-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/modigliani-server /modigliani-server
# DNS, HTTP, HTTPS, MQTT, MQTT/TLS, CoAP, local API
EXPOSE 53/udp 80 443 1883 8883 5683/udp 8080
VOLUME ["/data"]
ENTRYPOINT ["/modigliani-server"]
CMD ["--profiles", "/profiles", "--config", "/config/config.yaml"]

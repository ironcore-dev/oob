FROM golang:1.22 as builder

ARG TARGETARCH
WORKDIR /oob

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY api/ api/
COPY bmc/ bmc/
COPY console/ console/
COPY controllers/ controllers/
COPY internal/ internal/
COPY servers/ servers/
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -o oob main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -o oob-console console/main.go

FROM debian:bookworm-20240211-slim

WORKDIR /

RUN apt-get update && \
    apt-get install -y freeipmi-tools ipmitool --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

USER 65532:65532
ENTRYPOINT ["/oob"]

COPY --from=builder /oob/oob .
COPY --from=builder /oob/oob-console .

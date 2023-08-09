# Build the manager binary
FROM golang:1.21 as builder

ARG TARGETARCH

WORKDIR /workspace

ENV GOPRIVATE='github.com/onmetal/*'
COPY hack/setup-git-redirect.sh hack/

COPY go.mod go.mod
COPY go.sum go.sum

RUN --mount=type=ssh --mount=type=secret,id=github_pat GITHUB_PAT_PATH=/run/secrets/github_pat \
    hack/setup-git-redirect.sh && \
    mkdir -p -m 0600 ~/.ssh && \
    ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts && \
    go mod download

COPY api/ api/
COPY bmc/ bmc/
COPY controllers/ controllers/
COPY log/ log/
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -o manager main.go


FROM debian:bookworm-20230725-slim

WORKDIR /

RUN apt-get update && \
    apt-get install -y freeipmi-tools ipmitool --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

USER 65532:65532
ENTRYPOINT ["/manager"]

COPY --from=builder /workspace/manager .

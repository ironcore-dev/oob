FROM golang:1.22 as builder

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
COPY internal/ internal/
COPY servers/ servers/
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -o oob main.go

RUN --mount=type=ssh --mount=type=secret,id=github_pat GITHUB_PAT_PATH=/run/secrets/github_pat go get github.com/onmetal/oob-console && go install github.com/onmetal/oob-console

FROM debian:bookworm-20240211-slim

WORKDIR /

RUN apt-get update && \
    apt-get install -y freeipmi-tools ipmitool --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

USER 65532:65532
ENTRYPOINT ["/oob"]

COPY --from=builder /workspace/oob .
COPY --from=builder /go/bin/oob-console .

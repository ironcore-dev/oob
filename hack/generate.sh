#!/bin/sh
set -eu

VGOPATH="$(mktemp -d)"
MODELSSCHEMA="$(mktemp)"
trap 'rm -rf "$VGOPATH" "$MODELSSCHEMA"' EXIT
go mod download && go run github.com/ironcore-dev/vgopath -o "$VGOPATH"
GOROOT="${GOROOT:-"$(go env GOROOT)"}"
export GOROOT
GOPATH="$VGOPATH"
export GOPATH
GO111MODULE=off
export GO111MODULE

APIS_APPLYCONFIGURATION='github.com/onmetal/oob-operator/api/v1alpha1'
APIS_OPENAPI="k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/api/resource,k8s.io/api/core/v1,$APIS_APPLYCONFIGURATION"

go run k8s.io/code-generator/cmd/openapi-gen \
  --output-base "$GOPATH/src" \
  --go-header-file hack/boilerplate.go.txt \
  --input-dirs "$APIS_OPENAPI" \
  --output-package "github.com/onmetal/oob-operator/openapi" \
  -O zz_generated.openapi \
  --report-filename "openapi/api_violations.report"

go run github.com/ironcore-dev/ironcore/models-schema --openapi-package "github.com/onmetal/oob-operator/openapi" --openapi-title "oob-operator" > "$MODELSSCHEMA"
go run k8s.io/code-generator/cmd/applyconfiguration-gen \
  --output-base "$GOPATH/src" \
  --go-header-file hack/boilerplate.go.txt \
  --input-dirs "$APIS_APPLYCONFIGURATION" \
  --openapi-schema "$MODELSSCHEMA" \
  --output-package "github.com/onmetal/oob-operator/applyconfiguration"

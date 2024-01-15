//go:build tools
// +build tools

package main

import (
	_ "github.com/onsi/ginkgo/v2/ginkgo"
	_ "k8s.io/code-generator/cmd/applyconfiguration-gen"
	_ "k8s.io/code-generator/cmd/openapi-gen"
	_ "sigs.k8s.io/controller-runtime/tools/setup-envtest"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
	_ "sigs.k8s.io/kustomize/kustomize/v4"

	_ "github.com/ironcore-dev/ironcore/models-schema"
	_ "github.com/ironcore-dev/vgopath"
)

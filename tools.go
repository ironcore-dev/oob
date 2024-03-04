// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tools
// +build tools

package main

import (
	_ "github.com/google/addlicense"
	_ "github.com/onsi/ginkgo/v2/ginkgo"
	_ "k8s.io/code-generator/cmd/applyconfiguration-gen"
	_ "k8s.io/code-generator/cmd/openapi-gen"
	_ "sigs.k8s.io/controller-runtime/tools/setup-envtest"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
	_ "sigs.k8s.io/kustomize/kustomize/v4"

	_ "github.com/ironcore-dev/ironcore/models-schema"
	_ "github.com/ironcore-dev/vgopath"
)

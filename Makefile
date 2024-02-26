SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	@go run sigs.k8s.io/controller-tools/cmd/controller-gen rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: ## Generate DeepCopy, DeepCopyInto, and DeepCopyObject method implementations and applyconfiguration.
	@go run sigs.k8s.io/controller-tools/cmd/controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
	@hack/generate.sh

.PHONY: fmt
fmt: ## Run go fmt against code.
	@go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	@go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run tests.
	@go run github.com/onsi/ginkgo/v2/ginkgo -r --race --randomize-suites --randomize-all --keep-going --timeout=9223372036s -v

.PHONY: build
build: generate fmt vet ## Build manager binary.
	@go build -o oob .

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@go run sigs.k8s.io/kustomize/kustomize/v4 build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@go run sigs.k8s.io/kustomize/kustomize/v4 build config/crd | kubectl delete --ignore-not-found=true -f -

.PHONY: addlicense
addlicense: ## Add license headers to all go files.
	find . -name '*.go' -exec go run github.com/google/addlicense -f hack/license-header.txt {} +

.PHONY: checklicense
checklicense: ## Check that every file has a license header present.
	find . -name '*.go' -exec go run github.com/google/addlicense  -check -c 'OnMetal authors' {} +

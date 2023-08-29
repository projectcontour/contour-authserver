# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

BIN := contour-authserver

REPO := github.com/projectcontour/contour-authserver
SHA := $(shell git rev-parse --short=8 HEAD)
VERSION := $(shell git describe --exact-match 2>/dev/null || basename $$(git describe --all --long 2>/dev/null))
BUILDDATE := $(shell TZ=GMT date '+%Y-%m-%dT%R:%S%z')

GO_BUILD_LDFLAGS := \
	-s \
	-w \
	-X $(REPO)/pkg/version.Progname=$(BIN) \
	-X $(REPO)/pkg/version.Version=$(VERSION) \
	-X $(REPO)/pkg/version.Sha=$(SHA) \
	-X $(REPO)/pkg/version.BuildDate=$(BUILDDATE)

# Image URL to use all building/pushing image targets
IMG ?= $(BIN):$(VERSION)

all: build

test: check

.PHONY: check
check: ## Run tests
check: fmt vet lint
	go test ./... -coverprofile cover.out

.PHONY: build
build: ## Build controller binary
build: fmt vet
	go build -mod=readonly -ldflags "$(GO_BUILD_LDFLAGS)" -o bin/$(BIN) main.go

.PHONY: run
run: ## Run against the configured Kubernetes cluster in ~/.kube/config
run: fmt vet
	go run ./main.go

.PHONY: deploy
deploy: ## Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy:
	cd config/testserver && kustomize edit set image controller=${IMG}
	kustomize build config/default | kubectl apply -f -

.PHONY: fmt
fmt: ## Run go fmt against code
	go fmt -mod=readonly ./...

.PHONY: vet
vet: ## Run go vet against code
	go vet -mod=readonly -ldflags "$(GO_BUILD_LDFLAGS)" ./...

.PHONY: lint
lint: ## Run linters
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.2 run -v --exclude-use-default=false

.PHONY: docker-build
docker-build: ## Build the docker image
	docker build . -t ${IMG}

.PHONY: docker-push
docker-push: ## Push the docker image
	docker push ${IMG}

.PHONY: release
release: ## Build and publish a release to Github
	# Check there is a token.
	[[ -n "$$GITHUB_TOKEN" ]] || [[ -r ~/.config/goreleaser/github_token ]]
	# Check we are on a tag.
	git describe --exact-match >/dev/null
	# Do a full dry-run.
	goreleaser check
	SHA=$(SHA) VERSION=$(VERSION) goreleaser release --clean

.PHONY: clean
clean:
	@rm -rf cover.out
	@rm -rf bin
	@rm -rf dist

.PHONY: help
help:
	@echo "$(BIN)"
	@echo
	@echo Targets:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9._-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

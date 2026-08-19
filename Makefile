GO ?= go

.PHONY: build test fmt vet staticcheck vuln ci

build:
	$(GO) build ./...

test:
	$(GO) test -race ./...

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

staticcheck:
	$(GO) tool staticcheck ./...

vuln:
	$(GO) tool govulncheck ./...

ci: vet build test staticcheck vuln

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
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

ci: vet build test staticcheck vuln

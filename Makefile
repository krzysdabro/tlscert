BINARY := tlscert
BUILDOPTS := CGO_ENABLED=0
GOFILES := $(shell git ls-files '*.go')
LDFLAGS := $(LDFLAGS) -s -w

.PHONY: all
all: build

.PHONY: build
build:
	@$(BUILDOPTS) go build -v -ldflags="$(LDFLAGS)" -o $(BINARY)

.PHONY: fmt
fmt:
	@gofmt -s -w $(GOFILES)

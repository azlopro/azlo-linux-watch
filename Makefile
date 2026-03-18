BIN     := azlo-linux-watch
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -trimpath -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build build-amd64 build-arm64 vet clean

build:
	go build $(LDFLAGS) -o $(BIN) .

build-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN)-amd64 .

build-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN)-arm64 .

vet:
	go vet ./...

clean:
	rm -f $(BIN) $(BIN)-amd64 $(BIN)-arm64

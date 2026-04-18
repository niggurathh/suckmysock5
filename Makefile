BINARY=suckmysock5
VERSION=1.0.0

.PHONY: all clean linux-amd64 linux-386 windows-amd64 windows-386 darwin-amd64 darwin-arm64

all: linux-amd64 linux-386 windows-amd64 windows-386 darwin-amd64 darwin-arm64

linux-amd64:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(BINARY)-linux-amd64 .

linux-386:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o bin/$(BINARY)-linux-386 .

windows-amd64:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(BINARY)-windows-amd64.exe .

windows-386:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o bin/$(BINARY)-windows-386.exe .

darwin-amd64:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(BINARY)-darwin-amd64 .

darwin-arm64:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o bin/$(BINARY)-darwin-arm64 .

clean:
	rm -rf bin/

build:
	go build -o $(BINARY) .

run-server:
	go run . -listen :8443 -socks :1080 -key test123

run-client:
	go run . -connect 127.0.0.1:8443 -key test123

test:
	go test -v ./...

BINARY_NAME=pnet

build:
	go build -o $(BINARY_NAME) ./cmd/pnet/main.go

test:
	go test ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf ~/.pnet

# Cross-compilation
build-all:
	# Mac (Intel)
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 ./cmd/pnet/main.go
	# Mac (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-darwin-arm64 ./cmd/pnet/main.go
	# Linux
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64 ./cmd/pnet/main.go
	# Windows
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows-amd64.exe ./cmd/pnet/main.go
	# Android (via Linux ARM64)
	GOOS=android GOARCH=arm64 go build -o $(BINARY_NAME)-android-arm64 ./cmd/pnet/main.go

.PHONY: build test clean build-all

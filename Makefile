VERSION=1.3.2
PACKAGES_DIR=compiled_packages

all: test build

test:
	go fmt ./...
	go vet -v ./...

clean:
	rm -f ${PACKAGES_DIR}/*

run:
	go run ./cmd/neigh2route

build:
	CGO_ENABLED=1 GOARCH=amd64 GOOS=linux go build -o ${PACKAGES_DIR}/neigh2route-${VERSION}-linux ./cmd/neigh2route

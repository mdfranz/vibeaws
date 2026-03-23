INSTALL_DIR=$(HOME)/.local/bin
BINARY_NAME=wolkfind

.PHONY: all build clean install test help

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) main.go

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@cp $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)

test:
	@echo "Running tests..."
	@go test ./...

help:
	@echo "Available targets:"
	@echo "  build   - Compile the binary"
	@echo "  clean   - Remove the binary"
	@echo "  install - Install the binary to GOBIN"
	@echo "  test    - Run go tests"
	@echo "  help    - Show this help message"

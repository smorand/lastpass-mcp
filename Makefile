.PHONY: build build-all install install-launcher uninstall clean clean-all rebuild rebuild-all test test-unit test-race test-functional test-all fmt vet lint check run run-up run-down info help list-commands init-mod init-deps docker docker-build docker-push
.PHONY: plan deploy undeploy init-plan init-deploy init-destroy terraform-help check-init update-backend configure-docker-auth

# Detect current platform
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)
CURRENT_PLATFORM=$(GOOS)-$(GOARCH)

# Docker configuration
PROJECT_NAME := $(shell basename $(CURDIR))
MAKE_DOCKER_PREFIX ?=
DOCKER_TAG ?= latest

# Detect optional directories for Docker build
HAS_INTERNAL := $(shell test -d internal && echo "yes" || echo "no")
HAS_DATA := $(shell test -d data && echo "yes" || echo "no")

# Detect install directory based on user privileges (root vs non-root)
IS_ROOT=$(shell [ $$(id -u) -eq 0 ] && echo "yes" || echo "no")
ifeq ($(IS_ROOT),yes)
	DEFAULT_INSTALL_DIR=/usr/local/bin
	DEFAULT_LIB_DIR=/usr/local/lib
	SUDO_CMD=
else
	DEFAULT_INSTALL_DIR=$(HOME)/.local/bin
	DEFAULT_LIB_DIR=$(HOME)/.local/lib
	SUDO_CMD=
endif

# Detect all commands in cmd/ directory
COMMANDS=$(shell find cmd -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)

# Default binary name (first command in cmd/ directory)
FIRST_CMD=$(shell ls cmd 2>/dev/null | head -1)
DEFAULT_BINARY_NAME=$(if $(FIRST_CMD),$(FIRST_CMD),$(shell basename $$(pwd)))

# Module name - override this if your module path differs from binary name
# Example: MODULE_NAME=github.com/myorg/myproject
MODULE_NAME ?= $(DEFAULT_BINARY_NAME)

# Find all Go source files for rebuild detection
GO_SOURCES=$(shell find . -name '*.go' -type f 2>/dev/null | grep -v '_test.go')

# Detect if functional tests exist
HAS_FUNCTIONAL_TESTS=$(shell [ -f tests/run_tests.sh ] && echo "yes" || echo "no")

# Build configuration
BUILD_DIR=bin
GO_MOD_PATH=go.mod
GO_SUM_PATH=go.sum

# All platforms to build for build-all
ALL_PLATFORMS=linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64

# Generate list of all binaries for current platform
CURRENT_BINARIES=$(foreach cmd,$(COMMANDS),$(BUILD_DIR)/$(cmd)-$(CURRENT_PLATFORM))

# Generate list of all binaries for all platforms
ALL_BINARIES=$(foreach cmd,$(COMMANDS),$(foreach plat,$(ALL_PLATFORMS),$(BUILD_DIR)/$(cmd)-$(plat)$(if $(findstring windows,$(plat)),.exe,)))

# Generate list of all launcher scripts
ALL_LAUNCHERS=$(foreach cmd,$(COMMANDS),$(BUILD_DIR)/$(cmd).sh)

# Create build directory (order-only prerequisite)
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Define rule template for building a single command for current platform
define BUILD_CMD_CURRENT_RULE
$(BUILD_DIR)/$(1)-$(CURRENT_PLATFORM): $(GO_SUM_PATH) $(GO_SOURCES) | $(BUILD_DIR)
	@echo "Building $(1) for $(CURRENT_PLATFORM)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $$@ ./cmd/$(1)
ifeq ($(GOOS),darwin)
	@codesign -f -s - $$@
endif
	@echo "Done: $$@"
endef

# Define rule template for building a command for a specific platform
define BUILD_CMD_PLATFORM_RULE
$(BUILD_DIR)/$(1)-$(2)$(if $(findstring windows,$(2)),.exe,): $(GO_SUM_PATH) $(GO_SOURCES) | $(BUILD_DIR)
	@echo "Building $(1) for $(2)..."
	@GOOS=$(word 1,$(subst -, ,$(2))) GOARCH=$(word 2,$(subst -, ,$(2))) go build -o $$@ ./cmd/$(1)
ifeq ($(GOOS),darwin)
	$(if $(findstring darwin,$(2)),@codesign -f -s - $$@,)
endif
	@echo "Done: $$@"
endef

# Define rule template for creating launcher script
define BUILD_LAUNCHER_RULE
$(BUILD_DIR)/$(1).sh: $(foreach plat,$(ALL_PLATFORMS),$(BUILD_DIR)/$(1)-$(plat)$(if $(findstring windows,$(plat)),.exe,))
	@echo "Creating launcher script for $(1)..."
	@echo '#!/bin/bash' > $$@
	@echo '' >> $$@
	@echo '# Auto-generated launcher script for $(1)' >> $$@
	@echo '# Detects platform and executes the correct binary' >> $$@
	@echo '' >> $$@
	@echo '# Get the directory where this script is located' >> $$@
	@echo 'SCRIPT_DIR="$$$$(cd "$$$$(dirname "$$$${BASH_SOURCE[0]}")" && pwd)"' >> $$@
	@echo '' >> $$@
	@echo '# Detect OS' >> $$@
	@echo 'OS=$$$$(uname -s | tr "[:upper:]" "[:lower:]")' >> $$@
	@echo '' >> $$@
	@echo '# Detect architecture' >> $$@
	@echo 'ARCH=$$$$(uname -m)' >> $$@
	@echo '' >> $$@
	@echo '# Map architecture names to Go convention' >> $$@
	@echo 'case "$$$$ARCH" in' >> $$@
	@echo '    x86_64)' >> $$@
	@echo '        ARCH="amd64"' >> $$@
	@echo '        ;;' >> $$@
	@echo '    aarch64)' >> $$@
	@echo '        ARCH="arm64"' >> $$@
	@echo '        ;;' >> $$@
	@echo '    arm64)' >> $$@
	@echo '        ARCH="arm64"' >> $$@
	@echo '        ;;' >> $$@
	@echo '    *)' >> $$@
	@echo '        echo "Unsupported architecture: $$$$ARCH" >&2' >> $$@
	@echo '        exit 1' >> $$@
	@echo '        ;;' >> $$@
	@echo 'esac' >> $$@
	@echo '' >> $$@
	@echo '# Construct binary name' >> $$@
	@echo 'BINARY="$$$$SCRIPT_DIR/$(1)-$$$$OS-$$$$ARCH"' >> $$@
	@echo '' >> $$@
	@echo '# Check if binary exists' >> $$@
	@echo 'if [ ! -f "$$$$BINARY" ]; then' >> $$@
	@echo '    echo "Error: Binary not found for platform $$$$OS-$$$$ARCH" >&2' >> $$@
	@echo '    echo "Expected: $$$$BINARY" >&2' >> $$@
	@echo '    echo "" >&2' >> $$@
	@echo '    echo "Available binaries:" >&2' >> $$@
	@echo '    ls -1 "$$$$SCRIPT_DIR"/$(1)-* 2>/dev/null | sed "s|^|  |" >&2' >> $$@
	@echo '    exit 1' >> $$@
	@echo 'fi' >> $$@
	@echo '' >> $$@
	@echo '# Execute the binary with all arguments' >> $$@
	@echo 'exec "$$$$BINARY" "$$$$@"' >> $$@
	@chmod +x $$@
	@echo "Done: $$@"
endef

# Filter out current platform from ALL_PLATFORMS to avoid duplicate rules
OTHER_PLATFORMS=$(filter-out $(CURRENT_PLATFORM),$(ALL_PLATFORMS))

# Generate rules for each command (current platform)
$(foreach cmd,$(COMMANDS),$(eval $(call BUILD_CMD_CURRENT_RULE,$(cmd))))

# Generate rules for each command x other platform combinations (excludes current platform)
$(foreach cmd,$(COMMANDS),$(foreach plat,$(OTHER_PLATFORMS),$(eval $(call BUILD_CMD_PLATFORM_RULE,$(cmd),$(plat)))))

# Generate rules for launcher scripts
$(foreach cmd,$(COMMANDS),$(eval $(call BUILD_LAUNCHER_RULE,$(cmd))))

# Build for current platform only (incremental)
build: $(CURRENT_BINARIES)
	@echo "Build complete for $(CURRENT_PLATFORM)!"

# Build for all platforms and create launcher scripts (incremental)
build-all: $(ALL_BINARIES) $(ALL_LAUNCHERS)
	@echo "Build complete for all platforms!"

rebuild: clean-all build

rebuild-all: clean-all build-all

# Generate go.sum
$(GO_SUM_PATH): $(GO_MOD_PATH)
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@touch $(GO_SUM_PATH)
	@echo "Dependencies downloaded"

# Initialize go.mod - dedicated target for module initialization
init-mod:
	@if [ -f "$(GO_MOD_PATH)" ]; then \
		echo "go.mod already exists"; \
	else \
		echo "Initializing Go module $(MODULE_NAME)..."; \
		go mod init $(MODULE_NAME); \
		echo "Created $(GO_MOD_PATH)"; \
	fi

# Initialize dependencies (go.mod + go.sum) - run after init-mod
init-deps: init-mod
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies downloaded and go.sum updated"

# Generate go.mod (only if it doesn't exist) - implicit rule
$(GO_MOD_PATH):
	@echo "Initializing Go module..."
	@go mod init $(MODULE_NAME)

# Install binary (installs current platform binaries)
install: build
	@echo "Installing all commands for current platform ($(CURRENT_PLATFORM))..."
ifndef TARGET
	@mkdir -p $(DEFAULT_INSTALL_DIR)
	@$(foreach cmd,$(COMMANDS), \
		if [ -f "$(BUILD_DIR)/$(cmd)-$(CURRENT_PLATFORM)" ]; then \
			echo "Installing $(cmd) to $(DEFAULT_INSTALL_DIR)..."; \
			cp $(BUILD_DIR)/$(cmd)-$(CURRENT_PLATFORM) $(DEFAULT_INSTALL_DIR)/$(cmd); \
		fi;)
ifeq ($(GOOS),darwin)
	@echo "Signing binaries for macOS..."
	@$(foreach cmd,$(COMMANDS), \
		if [ -f "$(DEFAULT_INSTALL_DIR)/$(cmd)" ]; then \
			codesign -f -s - $(DEFAULT_INSTALL_DIR)/$(cmd); \
		fi;)
endif
else
	@$(foreach cmd,$(COMMANDS), \
		if [ -f "$(BUILD_DIR)/$(cmd)-$(CURRENT_PLATFORM)" ]; then \
			echo "Installing $(cmd) to $(TARGET)..."; \
			cp $(BUILD_DIR)/$(cmd)-$(CURRENT_PLATFORM) $(TARGET)/$(cmd); \
		fi;)
ifeq ($(GOOS),darwin)
	@echo "Signing binaries for macOS..."
	@$(foreach cmd,$(COMMANDS), \
		if [ -f "$(TARGET)/$(cmd)" ]; then \
			codesign -f -s - $(TARGET)/$(cmd); \
		fi;)
endif
endif
	@echo "Installation complete!"

# Install launcher scripts (for multi-platform distribution)
install-launcher: build-all
	@echo "Installing launcher scripts for all commands..."
ifndef TARGET
	@mkdir -p $(DEFAULT_INSTALL_DIR)
	@$(foreach cmd,$(COMMANDS), \
		echo "Installing launcher for $(cmd) to $(DEFAULT_INSTALL_DIR)..."; \
		cp $(BUILD_DIR)/$(cmd).sh $(DEFAULT_INSTALL_DIR)/$(cmd); \
		mkdir -p $(DEFAULT_LIB_DIR)/$(cmd); \
		cp $(BUILD_DIR)/$(cmd)-linux-amd64 $(DEFAULT_LIB_DIR)/$(cmd)/ 2>/dev/null || true; \
		cp $(BUILD_DIR)/$(cmd)-darwin-amd64 $(DEFAULT_LIB_DIR)/$(cmd)/ 2>/dev/null || true; \
		cp $(BUILD_DIR)/$(cmd)-darwin-arm64 $(DEFAULT_LIB_DIR)/$(cmd)/ 2>/dev/null || true; \
		cp $(BUILD_DIR)/$(cmd)-windows-amd64.exe $(DEFAULT_LIB_DIR)/$(cmd)/ 2>/dev/null || true;)
ifeq ($(GOOS),darwin)
	@echo "Signing macOS binaries after install..."
	@$(foreach cmd,$(COMMANDS), \
		if [ -f "$(DEFAULT_LIB_DIR)/$(cmd)/$(cmd)-darwin-amd64" ]; then codesign -f -s - $(DEFAULT_LIB_DIR)/$(cmd)/$(cmd)-darwin-amd64; fi; \
		if [ -f "$(DEFAULT_LIB_DIR)/$(cmd)/$(cmd)-darwin-arm64" ]; then codesign -f -s - $(DEFAULT_LIB_DIR)/$(cmd)/$(cmd)-darwin-arm64; fi;)
endif
else
	@$(foreach cmd,$(COMMANDS), \
		echo "Installing launcher for $(cmd) to $(TARGET)..."; \
		cp $(BUILD_DIR)/$(cmd).sh $(TARGET)/$(cmd);)
	@echo "Note: Platform binaries remain in $(BUILD_DIR)/"
endif
	@echo "Installation complete!"

# Uninstall binaries
uninstall:
	@echo "Uninstalling all commands..."
	@$(foreach cmd,$(COMMANDS), \
		BINARY_PATH=$$(which $(cmd) 2>/dev/null); \
		if [ -n "$$BINARY_PATH" ]; then \
			echo "Removing $(cmd) from $$BINARY_PATH..."; \
			rm -f "$$BINARY_PATH" 2>/dev/null || sudo rm -f "$$BINARY_PATH"; \
			if [ -d "/usr/local/lib/$(cmd)" ]; then \
				echo "Removing platform binaries for $(cmd) from /usr/local/lib..."; \
				sudo rm -rf "/usr/local/lib/$(cmd)"; \
			fi; \
			if [ -d "$(HOME)/.local/lib/$(cmd)" ]; then \
				echo "Removing platform binaries for $(cmd) from ~/.local/lib..."; \
				rm -rf "$(HOME)/.local/lib/$(cmd)"; \
			fi; \
		fi;)
	@echo "Uninstallation complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f ./$(DEFAULT_BINARY_NAME)
	@echo "Clean complete!"

# Clean all (including go.mod and go.sum)
clean-all: clean
	@echo "Cleaning go.mod & go.sum..."
	@rm -f $(GO_MOD_PATH) $(GO_SUM_PATH)
	@echo "Clean complete!"

# Run functional tests (shell scripts in tests/)
test: build
ifeq ($(HAS_FUNCTIONAL_TESTS),yes)
	@echo "Running functional tests..."
	@chmod +x tests/*.sh 2>/dev/null || true
	@tests/run_tests.sh
else
	@echo "No functional tests found (tests/run_tests.sh not present)"
	@echo "Run 'make test-unit' for Go unit tests"
endif

# Run Go unit tests only
test-unit:
	@echo "Running Go unit tests..."
	@go test -v ./...

# Run Go unit tests with race detector
test-race:
	@echo "Running Go unit tests with race detector..."
	@go test -race -v ./...

# Run all tests (functional + unit)
test-all: build
	@echo "Running all tests..."
ifeq ($(HAS_FUNCTIONAL_TESTS),yes)
	@echo "=== Functional Tests ==="
	@chmod +x tests/*.sh 2>/dev/null || true
	@tests/run_tests.sh
endif
	@echo ""
	@echo "=== Go Unit Tests ==="
	@go test -v ./...
	@echo ""
	@echo "All tests completed!"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "Format complete!"

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "Vet complete!"

# Run linter (golangci-lint if available, otherwise fallback to vet)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running golangci-lint..."; \
		golangci-lint run ./...; \
		echo "Lint complete!"; \
	else \
		echo "golangci-lint not found, falling back to go vet..."; \
		echo "Install golangci-lint: https://golangci-lint.run/welcome/install/"; \
		$(MAKE) vet; \
	fi

# Run all checks (fmt, vet, lint, test-all)
check: fmt vet lint test-all
	@echo "All checks passed!"

# Run the application (passes arguments via ARGS and CMD variables)
run: build
ifndef CMD
	@echo "Error: Please specify CMD variable."
	@echo "Example: make run CMD=mycommand ARGS='--help'"
	@echo "Available commands:"
	@$(foreach cmd,$(COMMANDS),echo "  - $(cmd)";)
	@exit 1
else
	@echo "Running $(CMD)..."
	@$(BUILD_DIR)/$(CMD)-$(CURRENT_PLATFORM) $(ARGS)
endif

# List all available commands
list-commands:
	@echo "Available commands in this project:"
	@$(foreach cmd,$(COMMANDS),echo "  - $(cmd)";)

# Start services with docker compose
run-up: docker-build
	@echo "Starting services..."
	@PROJECT_NAME=$(PROJECT_NAME) DOCKER_PREFIX=$(MAKE_DOCKER_PREFIX) DOCKER_TAG=$(DOCKER_TAG) docker compose up -d
	@echo "Services started!"

# Stop services with docker compose
run-down:
	@echo "Stopping services..."
	@PROJECT_NAME=$(PROJECT_NAME) DOCKER_PREFIX=$(MAKE_DOCKER_PREFIX) DOCKER_TAG=$(DOCKER_TAG) docker compose down
	@echo "Services stopped!"

# Build and push all Docker images (linux-amd64)
docker: docker-build docker-push

# Build Docker images for all commands
docker-build:
	@for cmd in $(COMMANDS); do \
		echo "Building Docker image: $(MAKE_DOCKER_PREFIX)$(PROJECT_NAME)-$$cmd:$(DOCKER_TAG)"; \
		docker build -t $(MAKE_DOCKER_PREFIX)$(PROJECT_NAME)-$$cmd:$(DOCKER_TAG) \
			--build-arg GO_BIN=$$cmd \
			--build-arg HAS_INTERNAL=$(HAS_INTERNAL) \
			--build-arg HAS_DATA=$(HAS_DATA) \
			.; \
	done

# Push Docker images for all commands
docker-push:
	@for cmd in $(COMMANDS); do \
		echo "Pushing: $(MAKE_DOCKER_PREFIX)$(PROJECT_NAME)-$$cmd:$(DOCKER_TAG)"; \
		docker push $(MAKE_DOCKER_PREFIX)$(PROJECT_NAME)-$$cmd:$(DOCKER_TAG); \
	done

# Show current platform info
info:
	@echo "Current platform: $(CURRENT_PLATFORM)"
	@echo "Build directory: $(BUILD_DIR)"
	@echo "Commands: $(COMMANDS)"

# Help
help:
	@echo "Available targets:"
	@echo "  build            - Build binaries for current platform ($(CURRENT_PLATFORM))"
	@echo "  build-all        - Build for all platforms and create launcher scripts"
	@echo "  run              - Build and run the binary"
	@echo "  rebuild          - Clean all and rebuild for current platform"
	@echo "  rebuild-all      - Clean all and rebuild for all platforms"
	@echo "  install          - Install current platform binaries (root: /usr/local/bin, user: ~/.local/bin, or TARGET)"
	@echo "  install-launcher - Install launcher scripts with all platform binaries"
	@echo "  uninstall        - Remove installed binaries"
	@echo "  clean            - Remove build artifacts"
	@echo "  clean-all        - Remove build artifacts, go.mod, and go.sum"
	@echo "  init-mod         - Initialize go.mod with module name (uses MODULE_NAME)"
	@echo "  init-deps        - Initialize go.mod and download dependencies"
	@echo "  test             - Run functional tests (shell scripts in tests/)"
	@echo "  test-unit        - Run Go unit tests only"
	@echo "  test-race        - Run Go unit tests with race detector"
	@echo "  test-all         - Run all tests (functional + unit)"
	@echo "  fmt              - Format code"
	@echo "  vet              - Run go vet"
	@echo "  lint             - Run golangci-lint (or go vet if not installed)"
	@echo "  check            - Run fmt, vet, lint, and test-all"
	@echo "  run-up           - Build Docker images and start docker compose"
	@echo "  run-down         - Stop docker compose services"
	@echo "  docker           - Build and push Docker images (linux-amd64)"
	@echo "  docker-build     - Build Docker images for all commands"
	@echo "  docker-push      - Push Docker images to registry"
	@echo "  list-commands    - List all available commands (multi-command projects)"
	@echo "  info             - Show current platform and project information"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Terraform targets:"
	@echo "  plan             - Plan main infrastructure changes"
	@echo "  deploy           - Deploy main infrastructure (Docker + Cloud Run)"
	@echo "  undeploy         - Destroy main infrastructure"
	@echo "  init-plan        - Plan initialization resources"
	@echo "  init-deploy      - Deploy initialization resources"
	@echo "  init-destroy     - Destroy initialization (DANGEROUS!)"
	@echo "  terraform-help   - Show detailed Terraform help"
	@echo ""
	@echo "Available commands:"
	@$(foreach cmd,$(COMMANDS),echo "  - $(cmd)";)
	@echo ""
	@echo "Examples:"
	@echo "  make build                     - Build all commands for current platform"
	@echo "  make build-all                 - Build all commands for all platforms"
	@echo "  make run CMD=mycommand         - Run specific command"
	@echo "  make run CMD=mycommand ARGS='--help' - Run with arguments"
	@echo "  make install                   - Install all commands for current platform"
	@echo "  make install-launcher          - Install launcher scripts for all commands"
	@echo ""
	@echo "Platform-specific binaries are created in $(BUILD_DIR)/ with suffixes:"
	@echo "  -linux-amd64        - Linux (Intel/AMD 64-bit)"
	@echo "  -linux-arm64        - Linux (ARM 64-bit / Graviton / Raspberry Pi)"
	@echo "  -darwin-amd64       - macOS (Intel)"
	@echo "  -darwin-arm64       - macOS (Apple Silicon)"
	@echo "  -windows-amd64.exe  - Windows (Intel/AMD 64-bit)"
	@echo ""
	@echo "Launcher scripts (.sh) automatically detect platform and execute the right binary."
	@echo ""
	@echo "Configuration variables:"
	@echo "  MODULE_NAME        - Go module name (default: $(MODULE_NAME))"
	@echo "                       Override with: make init-mod MODULE_NAME=github.com/myorg/myproject"
	@echo "  MAKE_DOCKER_PREFIX - Docker registry prefix (default: empty)"
	@echo "                       Example: MAKE_DOCKER_PREFIX=gcr.io/my-project/ make docker"
	@echo "  DOCKER_TAG         - Docker image tag (default: latest)"
	@echo "                       Example: DOCKER_TAG=v1.0.0 make docker"


# ============================================
# Terraform targets (project-specific)
# ============================================

# Check if init has been deployed (by checking if state backend exists)
check-init:
	@if [ ! -d "init/.terraform" ]; then \
		echo ""; \
		echo "ERROR: Initialization not completed!"; \
		echo ""; \
		echo "You must run initialization BEFORE deploying main infrastructure:"; \
		echo ""; \
		echo "  1. make init-plan       # Review what will be created"; \
		echo "  2. make init-deploy     # Deploy state backend & service accounts"; \
		echo "  3. make plan            # Then plan main infrastructure"; \
		echo "  4. make deploy          # Finally deploy main infrastructure"; \
		echo ""; \
		echo "The init step creates:"; \
		echo "  - Terraform state backend (GCS/S3/Azure Storage)"; \
		echo "  - Service accounts / IAM roles"; \
		echo "  - API enablement (GCP)"; \
		echo ""; \
		exit 1; \
	fi

# Update iac/provider.tf with backend configuration from init/
update-backend:
	@echo "Updating iac/provider.tf with backend configuration..."
	@if [ ! -d "init/.terraform" ]; then \
		echo "Error: init/.terraform not found. Run 'make init-deploy' first."; \
		exit 1; \
	fi
	@if [ ! -f "iac/provider.tf.template" ]; then \
		echo "Error: iac/provider.tf.template not found."; \
		exit 1; \
	fi
	@BACKEND_CONFIG=$$(cd init && terraform output -raw backend_config 2>/dev/null); \
	if [ -z "$$BACKEND_CONFIG" ]; then \
		echo "Error: Could not get backend_config from terraform output."; \
		exit 1; \
	fi; \
	PLACEHOLDER_LINE=$$(grep -n "BACKEND_PLACEHOLDER" iac/provider.tf.template | cut -d: -f1 | head -1); \
	if [ -z "$$PLACEHOLDER_LINE" ]; then \
		echo "Error: # BACKEND_PLACEHOLDER not found in template."; \
		exit 1; \
	fi; \
	head -n $$((PLACEHOLDER_LINE - 1)) iac/provider.tf.template > iac/provider.tf; \
	echo "$$BACKEND_CONFIG" >> iac/provider.tf; \
	tail -n +$$((PLACEHOLDER_LINE + 1)) iac/provider.tf.template >> iac/provider.tf; \
	echo "Successfully updated iac/provider.tf"; \
	echo ""; \
	echo "Backend configuration:"; \
	echo "$$BACKEND_CONFIG"

# Configure Docker authentication for Artifact Registry (GCP)
configure-docker-auth:
	@REGISTRY_LOCATION=$$(cd init && terraform output -raw docker_registry_location 2>/dev/null); \
	if [ -n "$$REGISTRY_LOCATION" ]; then \
		echo "Configuring Docker authentication for $$REGISTRY_LOCATION..."; \
		gcloud auth configure-docker $$REGISTRY_LOCATION --quiet; \
		echo "Docker authentication configured"; \
	fi

# IAC targets (main infrastructure)
plan: check-init
	@echo "Planning main infrastructure..."
	cd iac && terraform init -reconfigure && terraform plan

deploy: check-init
	@echo "Deploying main infrastructure..."
	cd iac && terraform init -reconfigure && terraform apply -auto-approve

undeploy: check-init
	@echo "Destroying main infrastructure..."
	cd iac && terraform init -reconfigure && terraform destroy -auto-approve

# Init targets (backend, state, service accounts)
init-plan:
	@echo "Planning initialization..."
	cd init && terraform init -reconfigure && terraform plan

init-deploy:
	@echo "Deploying initialization..."
	cd init && terraform init -reconfigure && terraform apply -auto-approve
	@$(MAKE) update-backend
	@$(MAKE) configure-docker-auth
	@echo ""
	@echo "Initialization complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Run: make plan"
	@echo "  2. Run: make deploy"

init-destroy:
	@echo "Destroying initialization resources..."
	@echo "WARNING: This will destroy state backend and service accounts!"
	@read -p "Are you sure? (yes/no): " answer && [ "$$answer" = "yes" ]
	cd init && terraform init -reconfigure && terraform destroy -auto-approve

# Help
terraform-help:
	@echo "Terraform Makefile Targets:"
	@echo ""
	@echo "Deployment Workflow (First Time):"
	@echo "  1. make init-plan       - Plan initialization (state backend, service accounts)"
	@echo "  2. make init-deploy     - Deploy initialization (auto-updates backend + docker auth)"
	@echo "  3. make plan            - Plan main infrastructure"
	@echo "  4. make deploy          - Deploy main infrastructure"
	@echo ""
	@echo "Main Infrastructure:"
	@echo "  make plan               - Plan main infrastructure changes"
	@echo "  make deploy             - Deploy main infrastructure"
	@echo "  make undeploy           - Destroy main infrastructure"
	@echo ""
	@echo "Initialization (One-time Setup):"
	@echo "  make init-plan          - Plan initialization resources"
	@echo "  make init-deploy        - Deploy initialization resources"
	@echo "  make init-destroy       - Destroy initialization (DANGEROUS!)"
	@echo ""
	@echo "Utilities:"
	@echo "  make update-backend       - Manually regenerate iac/provider.tf"
	@echo "  make configure-docker-auth - Manually configure Docker registry auth"
	@echo ""
	@echo "Note: You must run 'make init-deploy' BEFORE running 'make deploy'"

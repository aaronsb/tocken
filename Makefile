# tocken — make pattern: every target has a ## description for `make help`.
# Run `make` with no args to list targets.

NPM ?= npm
APP_DIR := app
TAURI_DIR := app/src-tauri
ADR := docs/scripts/adr

.DEFAULT_GOAL := help

.PHONY: help
help: ## show this help
	@awk 'BEGIN { FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n" } \
		/^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)

.PHONY: dev
dev: ## run the Tauri app in dev mode (NPM=pnpm to override)
	cd $(APP_DIR) && $(NPM) install && $(NPM) run tauri dev

.PHONY: build
build: ## cargo build (debug)
	cd $(TAURI_DIR) && cargo build

.PHONY: release
release: ## cargo build --release
	cd $(TAURI_DIR) && cargo build --release

.PHONY: test
test: ## cargo test --lib
	cd $(TAURI_DIR) && cargo test --lib

.PHONY: fmt
fmt: ## cargo fmt
	cd $(TAURI_DIR) && cargo fmt

.PHONY: fmt-check
fmt-check: ## cargo fmt --check (CI-style)
	cd $(TAURI_DIR) && cargo fmt --check

.PHONY: lint
lint: ## cargo clippy
	cd $(TAURI_DIR) && cargo clippy --all-targets -- -D warnings

.PHONY: check
check: fmt-check lint test ## run fmt-check + lint + test (pre-PR gate)

.PHONY: clean
clean: ## cargo clean
	cd $(TAURI_DIR) && cargo clean

.PHONY: adr-list
adr-list: ## list ADRs
	@$(ADR) list

.PHONY: adr-lint
adr-lint: ## lint ADR files
	@$(ADR) lint

.PHONY: adr-index
adr-index: ## regenerate docs/architecture/README.md index
	@$(ADR) index

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
build: ## cargo build (debug, workspace)
	cargo build --workspace

.PHONY: release
release: ## cargo build --release (workspace)
	cargo build --workspace --release

.PHONY: test
test: ## cargo test --lib (workspace)
	cargo test --workspace --lib

.PHONY: test-hw
test-hw: ## run #[ignore]'d tests that require a YubiKey (serial; touch when prompted)
	cargo test --workspace --lib -- --ignored --test-threads=1

.PHONY: fmt
fmt: ## cargo fmt (workspace)
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## cargo fmt --check (workspace, CI-style)
	cargo fmt --all --check

.PHONY: lint
lint: ## cargo clippy (workspace)
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: check
check: fmt-check lint test ## run fmt-check + lint + test (pre-PR gate)

.PHONY: check-yubi
check-yubi: check test-hw ## check + the hardware-gated tests; touch the YubiKey when prompted

.PHONY: test-secrets
test-secrets: ## generate /tmp/tocken-import-test.txt for smoke-testing the file picker
	@scripts/gen-test-secrets.sh

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

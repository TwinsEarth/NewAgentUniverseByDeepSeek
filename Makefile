# NewAgentUniverseByDeepSeek — task entry points
#
#   make            # list every target
#   make check      # the full 25-gate suite (what CI runs)
#   make run        # build and start the node
#
# # WHY A MAKEFILE AND NOT ONLY DOCUMENTED COMMANDS
#
# Every command below is one somebody would otherwise retype from a document. The two that matter
# most are `CARGO_BUILD_JOBS` and the `--locked` flag:
#
#   * a parallel build of this 18-crate workspace can exhaust a small machine's memory, and it does
#     so SILENTLY -- see `docs/DEPLOYMENT.md`, where it is recorded as a real incident;
#   * without `--locked`, two builds of the same commit can resolve different dependency versions,
#     and a release is supposed to be reproducible.
#
# A target that gets both right every time is worth more than a paragraph that asks people to
# remember them.
#
# # WHAT IS DELIBERATELY NOT HERE
#
# No `make deploy`. Deployment is a decision about who may reach a node, whether the sandbox runs
# code, and what the data directory is -- three things this file cannot know. `docs/DEPLOYMENT.md`
# and `docs/ROLLBACK.md` cover them; a target that guessed would be worse than no target.

# 2 is the documented safe value on a 2 GB machine. Override with `make build JOBS=4`.
JOBS ?= 2

# Pinned rather than floating: `curve25519-dalek` is an edition-2024 crate, so anything older than
# 1.85 cannot build this workspace.
RUST ?= +1.85.0

export CARGO_BUILD_JOBS := $(JOBS)

.DEFAULT_GOAL := help
.PHONY: help build release run run-ephemeral p2p test check check-fast \
        deploy-check fmt clippy doc clean docker-build docker-up docker-down \
        docker-rollback verify-version help

help: ## Show this help
	@echo "NewAgentUniverseByDeepSeek — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------- build

build: ## Debug build of the three binaries (nau, nau-daemon, nau-p2p-daemon)
	cargo $(RUST) build --locked --bin nau --bin nau-daemon --bin nau-p2p-daemon

release: ## Release build of the three binaries
	cargo $(RUST) build --release --locked --bin nau --bin nau-daemon --bin nau-p2p-daemon

# ---------------------------------------------------------------- run
#
# `NAU_API_TOKENS` unset means READ-ONLY: the node starts, `/health` answers, and every mutating
# route is refused. That is the correct default and it surprises people, so `run` prints it.

run: release ## Run a node on 127.0.0.1:4002 with the default data directory
	@echo "--- NOTE: with NAU_API_TOKENS unset this node is READ-ONLY (default deny-all policy). ---"
	@echo "--- Set it to allow writes; see .env.example.                                    ---"
	@echo "--- The sandbox runs NOTHING unless NAU_SANDBOX_BACKEND=process.                  ---"
	./target/release/nau-daemon --api-addr 127.0.0.1:4002 --data-dir ./nau-data

run-ephemeral: release ## Run a node that persists nothing (in-memory state)
	./target/release/nau-daemon --ephemeral --api-addr 127.0.0.1:4002

p2p: release ## Run a node with a real libp2p swarm on /ip4/0.0.0.0/tcp/4001
	./target/release/nau-p2p-daemon \
		--api-addr 127.0.0.1:4002 --data-dir ./nau-data \
		--listen /ip4/0.0.0.0/tcp/4001 --room nau-dev \
		--register-self --agent-name local-node

# ---------------------------------------------------------------- test and verify

test: ## Run the workspace test suite
	cargo $(RUST) test --workspace

check: ## The full 25-gate suite; this is what CI runs
	node scripts/verify-all.mjs --allow-missing-tools

check-fast: ## The two gates that catch the most common mistakes
	node scripts/verify-all.mjs --only env-template --allow-missing-tools
	node scripts/verify-all.mjs --only doc-counts --allow-missing-tools

deploy-check: ## The 59 deployment checks against a freshly installed node
	node scripts/deploy-local.mjs --prefix ./.deploy-check

fmt: ## Format
	cargo $(RUST) fmt --all

clippy: ## Lint, warnings are errors
	cargo $(RUST) clippy --workspace --all-targets -- -D warnings

doc: ## Build the API documentation
	cargo $(RUST) doc --workspace --no-deps

verify-version: ## Show what the repository says its version is, and where from
	@echo "VERSION file:  $$(cat VERSION)"
	@echo "workspace:     $$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
	@echo "README title:  $$(head -1 README.md)"

# ---------------------------------------------------------------- containers
#
# Docker is optional and is not installed everywhere. These targets fail with a clear message
# rather than a shell error, because "docker: command not found" reads as a broken Makefile.

docker-build: ## Build the image
	@command -v docker >/dev/null 2>&1 || { \
		echo "docker is not installed or not on PATH."; \
		echo "The Dockerfile is still valid; see docs/DEPLOYMENT.md for the host-based path."; \
		exit 1; }
	docker build -t nau:3.9.9 --build-arg CARGO_BUILD_JOBS=$(JOBS) .

docker-up: ## Single node via compose
	@command -v docker >/dev/null 2>&1 || { echo "docker is not installed."; exit 1; }
	docker compose up --build -d
	docker compose ps

docker-down: ## Stop, KEEPING the data volume
	@command -v docker >/dev/null 2>&1 || { echo "docker is not installed."; exit 1; }
	docker compose down
	@echo "The nau-data volume was kept. 'docker compose down -v' would delete it."

docker-rollback: ## Roll back to the image tagged 'nau:rollback'
	@command -v docker >/dev/null 2>&1 || { echo "docker is not installed."; exit 1; }
	@docker image inspect nau:rollback >/dev/null 2>&1 || { \
		echo "No image tagged 'nau:rollback'."; \
		echo "Tag the version you are rolling back to FIRST: docker tag nau:3.9.8 nau:rollback"; \
		exit 1; }
	docker compose down
	docker tag nau:rollback nau:3.9.9
	docker compose up -d
	docker compose ps
	@echo "Now verify conservation and the audit tail — see docs/ROLLBACK.md section 3.3."

# ---------------------------------------------------------------- housekeeping

clean: ## Remove build output
	cargo $(RUST) clean
	rm -rf ./.deploy-check

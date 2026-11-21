.DEFAULT_GOAL := all
python_sources = crates/pgsafe-python/pgsafe.pyi crates/pgsafe-python/tests
# where `make postgres` puts the database used by the integration tests
PGSAFE_TEST_DATABASE_URL ?= postgres://postgres:postgres@127.0.0.1:54329/postgres

.PHONY: .uv
.uv: ## Check that uv is installed
	@uv -V || echo 'Please install uv: https://docs.astral.sh/uv/getting-started/installation/'

.PHONY: install
install: .uv ## Install the python environment and the pre-commit hooks
	uv sync --all-groups --all-packages
	uvx prek install --install-hooks --overwrite

.PHONY: format-rs
format-rs: ## Format Rust code
	@cargo +nightly fmt --version
	cargo +nightly fmt --all

.PHONY: format-py
format-py: .uv ## Format Python code
	uv run --group linting ruff format $(python_sources)
	uv run --group linting ruff check --fix --fix-only $(python_sources)

.PHONY: format
format: format-rs format-py ## Format everything

.PHONY: lint-rs
lint-rs: ## Lint Rust code with rustfmt and clippy
	@cargo clippy --version
	cargo +nightly fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy --manifest-path crates/fuzz/Cargo.toml -- -D warnings
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

.PHONY: lint-py
lint-py: python-dev ## Lint Python code with ruff, basedpyright and stubtest
	uv run --group linting ruff format --check $(python_sources)
	uv run --group linting ruff check $(python_sources)
	uv run --group linting basedpyright
	# stubtest compares the stubs with the built module, hence python-dev
	uv run --group linting python -m mypy.stubtest pgsafe --allowlist crates/pgsafe-python/stubtest-allowlist.txt

.PHONY: lint
lint: lint-rs lint-py ## Lint everything

.PHONY: test
test: ## Run the Rust tests. The ones that need Postgres are skipped unless PGSAFE_TEST_DATABASE_URL is set
	cargo test --workspace

.PHONY: postgres
postgres: ## Start a throwaway Postgres in Docker for the integration tests
	docker run -d --rm --name pgsafe-test -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:54329:5432 postgres:18
	@echo 'stop it with: docker stop pgsafe-test'

.PHONY: test-postgres
test-postgres: ## Run the Rust tests including the ones against Postgres (see `make postgres`)
	PGSAFE_TEST_DATABASE_URL=$(PGSAFE_TEST_DATABASE_URL) cargo test --workspace

.PHONY: python-dev
python-dev: .uv ## Build the python package into the virtualenv
	uv run maturin develop --uv -m crates/pgsafe-python/Cargo.toml

.PHONY: python-test
python-test: python-dev ## Build the python package and run its tests
	uv run pytest crates/pgsafe-python/tests

.PHONY: testcov
testcov: ## Run the Rust tests with coverage and print a summary
	@cargo llvm-cov --version > /dev/null 2>&1 || echo 'Please run: `cargo install cargo-llvm-cov`'
	cargo llvm-cov --workspace --summary-only

.PHONY: fuzz
fuzz: ## Fuzz `check` with arbitrary input
	cargo +nightly fuzz run --fuzz-dir crates/fuzz check --release

.PHONY: fuzz-mutate
fuzz-mutate: ## Fuzz `check` with mutations of the test cases
	cargo +nightly fuzz run --fuzz-dir crates/fuzz mutate --release

.PHONY: all
all: format lint test python-test ## Format, lint and test

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

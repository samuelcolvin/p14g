.DEFAULT_GOAL := all
python_sources = crates/p14g-python/p14g.pyi crates/p14g-python/tests crates/fuzz-agent
# where `make postgres` puts the database used by the integration tests
P14G_TEST_DATABASE_URL ?= postgres://postgres:postgres@127.0.0.1:54329/postgres

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
	uv run --group linting --group fuzz-agent basedpyright
	# stubtest compares the stubs with the built module, hence python-dev
	uv run --group linting python -m mypy.stubtest p14g --allowlist crates/p14g-python/stubtest-allowlist.txt

.PHONY: lint
lint: lint-rs lint-py ## Lint everything

.PHONY: test
test: ## Run the Rust tests. The ones that need Postgres are skipped unless P14G_TEST_DATABASE_URL is set
	cargo test --workspace

.PHONY: postgres
postgres: ## Start a throwaway Postgres in Docker for the integration tests
	docker run -d --rm --name p14g-test -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:54329:5432 postgres:18
	@echo 'stop it with: docker stop p14g-test'

.PHONY: test-postgres
test-postgres: ## Run the Rust tests including the ones against Postgres (see `make postgres`)
	P14G_TEST_DATABASE_URL=$(P14G_TEST_DATABASE_URL) cargo test --workspace

.PHONY: python-dev
python-dev: .uv ## Build the python package into the virtualenv
	uv run maturin develop --uv -m crates/p14g-python/Cargo.toml

.PHONY: python-test
python-test: python-dev ## Build the python package and run its tests
	uv run pytest crates/p14g-python/tests

.PHONY: testcov
testcov: ## Run the Rust tests with coverage and print a summary
	@cargo llvm-cov --version > /dev/null 2>&1 || echo 'Please run: `cargo install cargo-llvm-cov`'
	cargo llvm-cov --workspace --summary-only

# The fuzz targets also check their output against Postgres when P14G_TEST_DATABASE_URL is set, see `make postgres`:
#     P14G_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:54329/postgres make fuzz-mutate
.PHONY: fuzz
fuzz: ## Fuzz `rewrite` with arbitrary input
	cargo +nightly fuzz run --fuzz-dir crates/fuzz rewrite --release

.PHONY: fuzz-mutate
fuzz-mutate: ## Fuzz `rewrite` with mutations of the test cases
	cargo +nightly fuzz run --fuzz-dir crates/fuzz mutate --release

.PHONY: fuzz-agent
fuzz-agent: python-dev ## Have an LLM attack p14g (see crates/fuzz-agent). ARGS='--rounds 1' passes options on
	cd crates/fuzz-agent && P14G_TEST_DATABASE_URL=$(P14G_TEST_DATABASE_URL) uv run --group fuzz-agent python -m fuzz_agent $(ARGS)

.PHONY: test-fuzz-agent
test-fuzz-agent: python-dev ## Run the LLM fuzzer's API-free tests
	cd crates/fuzz-agent && uv run --group fuzz-agent python -m pytest tests

.PHONY: all
all: format lint test python-test ## Format, lint and test

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

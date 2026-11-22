.DEFAULT_GOAL := help

# a Postgres just for this example; port 54331 to stay clear of the main repo's `make postgres` on 54329
PORT ?= 54331

.PHONY: install
install: ## Create the python environment, building p14g from this repository
	uv sync

.PHONY: db
db: ## Start Postgres 18 in Docker
	docker run -d --rm --name p14g-example -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=example \
		-p 127.0.0.1:$(PORT):5432 postgres:18
	@until docker exec p14g-example pg_isready -U postgres -d example >/dev/null 2>&1; do sleep 0.5; done

.PHONY: db-stop
db-stop: ## Stop the Postgres container
	docker stop p14g-example

.PHONY: setup
setup: ## (Re)create roles, tables, row-level security, seed data and grants
	uv run python -m p14g_example.db

.PHONY: run
run: ## Run the server on http://127.0.0.1:8014
	uv run uvicorn p14g_example.main:app --reload --port 8014

.PHONY: test
test: ## Run the tests; they recreate the database
	uv run pytest

.PHONY: lint
lint: ## Check formatting and lint
	uv run ruff format --check
	uv run ruff check

.PHONY: format
format: ## Format and fix lint
	uv run ruff format
	uv run ruff check --fix

.PHONY: help
help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "%-10s %s\n", $$1, $$2}'

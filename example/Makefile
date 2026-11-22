.DEFAULT_GOAL := help

.PHONY: install
install: ## Create the python environment, building p14g from this repository
	uv sync

.PHONY: db
db: ## Start Postgres 18 in Docker on 127.0.0.1:54331, the compose file's `db` service
	docker compose up -d --wait db

.PHONY: up
up: ## Build and run everything in Docker: Postgres, setup, and the server on http://127.0.0.1:8014
	docker compose up --build

.PHONY: down
down: ## Stop the containers
	docker compose down

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

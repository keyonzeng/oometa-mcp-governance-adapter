.PHONY: help install dev test lint fmt scan serve demo clean

help:
	@echo "make install   - install the package"
	@echo "make dev       - install with dev extras"
	@echo "make test      - run the test suite"
	@echo "make lint      - run ruff"
	@echo "make fmt       - autoformat/fix with ruff"
	@echo "make demo      - seed demo data"
	@echo "make serve     - run the dashboard/API"
	@echo "make scan      - scan local MCP client configs"
	@echo "make clean     - remove caches and local state"

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

fmt:
	ruff check --fix src tests

demo:
	mcpcp demo seed

serve:
	mcpcp serve

scan:
	mcpcp scan

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ build dist *.egg-info

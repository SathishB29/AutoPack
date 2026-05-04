.PHONY: help install install-dev lint typecheck test check-file-length check pre-commit-install pre-commit-run

PYTHON ?= python

help:
	@echo "Available targets:"
	@echo "  install             Install package in editable mode"
	@echo "  install-dev         Install package with dev dependencies"
	@echo "  lint                Run Ruff checks"
	@echo "  typecheck           Run mypy on src/"
	@echo "  test                Run pytest"
	@echo "  check-file-length   Enforce max 400 lines per Python file"
	@echo "  check               Run lint + typecheck + test + file-length check"
	@echo "  pre-commit-install  Install git pre-commit hooks"
	@echo "  pre-commit-run      Run all pre-commit hooks"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e .[dev]

lint:
	$(PYTHON) -m ruff check src tests

typecheck:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest

check-file-length:
	$(PYTHON) scripts/check_python_file_length.py --max-lines 400

check: lint typecheck test check-file-length

pre-commit-install:
	$(PYTHON) -m pre_commit install
	$(PYTHON) -m pre_commit install --hook-type pre-push

pre-commit-run:
	$(PYTHON) -m pre_commit run --all-files

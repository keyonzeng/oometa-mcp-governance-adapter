# Contributing to mcp-control-plane

Thanks for your interest! This project aims to be serious, maintainable developer
infrastructure for governing MCP adoption.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test    # pytest
make lint    # ruff
```

Target Python 3.11+. Please keep the dependency footprint small.

## Guidelines

- **Add a test** for any behavior change (`tests/`). Security logic — the policy
  engine, scanner rules, gateway mediator, audit chain — must stay well covered.
- **Run `make lint test`** before opening a PR.
- **Keep the domain model (`models.py`) the single source of truth.** Subsystems
  depend on it; don't fork shapes.
- **New scanner rules** get a stable code (`MCP-XXX-NNN`), a severity, a concrete
  `detail`, and an actionable `remediation`.
- **New capability heuristics** go in `policy/builtin.py`; prefer conservative
  (raise risk when unsure).
- **New transports** implement a thin adapter that calls the existing
  `GatewayMediator` — don't reimplement policy.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the component map and the
`tools/list` / `tools/call` request lifecycles.

## License

By contributing you agree your contributions are licensed under Apache-2.0.

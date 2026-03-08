# Unit test process

## Requirements

- **Python 3.13** (matches Lambda runtime in `template.yaml`)
- **Virtual environment** (recommended): create with `python3.13 -m venv .venv`, activate with `source .venv/bin/activate` (Windows: `.venv\Scripts\activate`)
- **Dependencies**: from repo root, `pip install -r requirements.txt` (includes `boto3`, `eth-account`, `web3`, `pytest`)

The directories `.venv/` and `.pytest_cache/` are in `.gitignore` and are not tracked.

## Running tests

Run from the **repository root** (`mnemospark-backend/`) so that paths like `tests/` and `services/` resolve correctly.

```bash
# All unit tests
pytest tests/ -v

# Only unit tests (exclude integration)
pytest tests/unit/ -v

# Price-storage and estimate flows (unit)
pytest tests/unit/test_price_storage.py tests/unit/test_estimate_storage.py tests/unit/test_estimate_transfer.py -v
```

Unit tests use mocks and do **not** require AWS credentials. Integration tests under `tests/integration/` may call AWS and can be skipped or run with credentials; see AGENTS.md for details.

## CI

The `Deploy Staging` workflow installs dependencies and runs `pytest -q` from the repo root. Ensure local runs use the same Python version and repo root to avoid path or import differences.

# AGENTS.md

## Cursor Cloud specific instructions

### Project overview
mnemospark-backend is a serverless AWS Lambda backend (Python 3.13) using AWS SAM.
The supported production surface is:
- **Infrastructure**: root `template.yaml`
- **Runtime code**: `services/`
- **API contract/docs**: `docs/openapi.yaml` and `docs/*.md`
- **Tests**: `tests/unit/` and `tests/integration/`

Legacy proof-of-concept SAM examples are archived under `archive/examples/` and
are non-production historical artifacts.

### Development environment
- **Python 3.13** is required (matches Lambda runtime in `template.yaml`). Installed from `ppa:deadsnakes/ppa`.
- **Virtual environment** at `/workspace/.venv` — activate with `source /workspace/.venv/bin/activate`.
- **AWS SAM CLI** is installed in the venv (`sam --version`).
- **Docker** is required for `sam local invoke` / `sam local start-api`. The daemon needs `sudo dockerd &` on fresh VM starts; fuse-overlayfs and iptables-legacy are configured for nested-container operation. After starting dockerd, run `sudo chmod 666 /var/run/docker.sock` so the non-root user (ubuntu) can use Docker without sudo. Use this only in single-user dev environments; access to the socket is effectively root-equivalent, so in shared or production-like environments prefer adding the user to the `docker` group instead of making the socket world-writable.

### Key commands
| Task | Command |
|---|---|
| Lint | `source /workspace/.venv/bin/activate && ruff check services/ tests/` |
| Unit tests | `source /workspace/.venv/bin/activate && pytest tests/ -v` |
| SAM validate | `source /workspace/.venv/bin/activate && sam validate --template /workspace/template.yaml` |
| SAM build | `source /workspace/.venv/bin/activate && sam build --template-file /workspace/template.yaml` |
| Local invoke | `source /workspace/.venv/bin/activate && sam local invoke <FunctionName> -e <event.json> --template /workspace/template.yaml` |
| Local API | `source /workspace/.venv/bin/activate && sam local start-api --port 3001 --template /workspace/template.yaml` |

### Passing AWS credentials to `sam local invoke` / `sam local start-api`
SAM local containers do not inherit host environment variables. Pass credentials via `--env-vars`:
```bash
sam local invoke <FunctionName> -e event.json \
  --env-vars <(echo '{"<FunctionName>": {"AWS_ACCESS_KEY_ID": "...", "AWS_SECRET_ACCESS_KEY": "...", "AWS_DEFAULT_REGION": "..."}}')
```
Or create a local `env.json` file (gitignored; do NOT commit it) and pass `--env-vars env.json`.

### Linting scope
Run `ruff check` on source files only (`services/`, `tests/`) and avoid generated
build directories (`.aws-sam/build/`) which can include third-party code.

### Gotchas
- `sam validate --lint` reports W3005 warnings on auto-generated DependsOn for API key resources — these are cosmetic and come from SAM's internal resource generation, not from user-authored template code.
- Lambda functions require real AWS credentials for integration testing (STS, BCM, S3, Secrets Manager, DynamoDB). Without credentials, `sam local invoke` returns 500 with `InvalidClientTokenId` — this is expected.
- The `requests` library bundled with `aws-sam-cli` triggers a `RequestsDependencyWarning` about urllib3/chardet versions — safe to ignore.
- `.gitignore` excludes `.aws-sam/`, `.venv/`, `__pycache__/`, `.pytest_cache/`, `env.json`.

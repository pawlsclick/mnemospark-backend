# AGENTS.md

## Cursor Cloud specific instructions

### Project overview
mnemospark-backend is a serverless AWS Lambda backend (Python 3.13) using AWS SAM. Three Lambda functions live under `examples/`:
- **s3-cost-estimate-api** — S3 storage cost estimation via BCM Pricing Calculator
- **data-transfer-cost-estimate-api** — data transfer cost estimation via BCM Pricing Calculator
- **object-storage-management-api** — wallet-scoped S3 storage with AES-GCM envelope encryption (`cryptography` dependency)

### Development environment
- **Python 3.13** is required (matches Lambda runtime in `template.yaml`). Installed from `ppa:deadsnakes/ppa`.
- **Virtual environment** at `/workspace/.venv` — activate with `source /workspace/.venv/bin/activate`.
- **AWS SAM CLI** is installed in the venv (`sam --version`).
- **Docker** is required for `sam local invoke` / `sam local start-api`. The daemon needs `sudo dockerd &` on fresh VM starts; fuse-overlayfs and iptables-legacy are configured for nested-container operation.

### Key commands
| Task | Command |
|---|---|
| Lint | `source /workspace/.venv/bin/activate && ruff check examples/` |
| Unit tests | `source /workspace/.venv/bin/activate && pytest tests/ -v` |
| SAM validate | `cd examples/<api-dir> && sam validate` |
| SAM build | `cd examples/<api-dir> && sam build` |
| Local invoke | `cd examples/<api-dir> && sam local invoke <FunctionName> -e <event.json>` |
| Local API | `cd examples/<api-dir> && sam local start-api --port 3001` |

### Gotchas
- `sam validate` for `object-storage-management-api` requires `--region us-east-1` (no default region set in its samconfig.toml).
- `sam validate --lint` reports W3005 warnings on auto-generated DependsOn for API key resources — these are cosmetic and come from SAM's internal resource generation, not from user-authored template code.
- Lambda functions require real AWS credentials for integration testing (STS, BCM, S3, Secrets Manager, DynamoDB). Without credentials, `sam local invoke` returns 500 with `InvalidClientTokenId` — this is expected.
- The `requests` library bundled with `aws-sam-cli` triggers a `RequestsDependencyWarning` about urllib3/chardet versions — safe to ignore.
- No `.gitignore` excludes `.aws-sam/` build dirs or `.venv/` — be mindful when staging commits.

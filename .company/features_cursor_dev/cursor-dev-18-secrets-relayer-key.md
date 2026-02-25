# Cursor Dev: Secrets Manager for relayer private key

**ID:** cursor-dev-18  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–18) and design patterns live in this repo. Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement the [secrets_management.md](../infrastructure_design/secrets_management.md) spec for the **Base wallet relayer private key**: store and access it via **AWS Secrets Manager** only (never in environment variables or template parameters). This work has two parts:

1. **Template (SAM):** Remove `MNEMOSPARK_RELAYER_PRIVATE_KEY` from the upload Lambda’s `Environment.Variables`. Remove any `RelayerPrivateKey` (or equivalent) parameter used only for that value. Add an IAM policy to the upload Lambda’s execution role granting `secretsmanager:GetSecretValue` on the relayer secret (e.g. `arn:aws:secretsmanager:${Region}:${AccountId}:secret:mnemospark/relayer-private-key*`). Add an env var that passes the **secret identifier only** (not the key value), e.g. `MNEMOSPARK_RELAYER_SECRET_ID=mnemospark/relayer-private-key` (value may be a template parameter or constant per spec).

2. **Lambda code (storage-upload):** When `MNEMOSPARK_PAYMENT_SETTLEMENT_MODE=onchain`, resolve the relayer private key by calling `boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["MNEMOSPARK_RELAYER_SECRET_ID"])`. Use the returned value only in memory for signing; do not log it or include it in error messages. Remove any read of `MNEMOSPARK_RELAYER_PRIVATE_KEY` from `os.environ`. Cache the fetched key in module scope for the lifetime of the cold start if desired (still in-memory only).

Do **not** create the secret value in the template (the spec says an operator or pipeline creates it). Optionally add a short comment or README note that the secret `mnemospark/relayer-private-key` must exist before deployment, or add an optional SAM/CloudFormation snippet that creates an empty secret resource (value set separately by operator).

## References

- [infrastructure_design/secrets_management.md](../infrastructure_design/secrets_management.md) — full spec (scope, IAM, runtime flow, security rules, implementation checklist)
- [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md) — “No long-lived secrets in code; use IAM, SSM, or Secrets Manager”
- [template.yaml](../../template.yaml) — `StorageUploadFunction`, `UploadLambdaRole`
- [services/storage-upload/app.py](../../services/storage-upload/app.py) — where relayer key is used (on-chain settlement path)
- [AWS_DOCS_REFERENCES.md](AWS_DOCS_REFERENCES.md) — AWS docs for Secrets Manager, IAM

## Cloud Agent

- **Install (idempotent):** AWS CLI; SAM CLI if using SAM. Python deps for storage-upload (boto3, etc.) as in repo.
- **Start (if needed):** None.
- **Secrets (Cursor Settings → Cloud Agents → Secrets):** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` if validating or deploying.
- **Acceptance criteria (checkboxes):**
  - [ ] Template: `MNEMOSPARK_RELAYER_PRIVATE_KEY` removed from upload Lambda env; no parameter passes the key value. Upload Lambda has env var `MNEMOSPARK_RELAYER_SECRET_ID` (or equivalent) set to the secret ID (e.g. `mnemospark/relayer-private-key`).
  - [ ] Template: Upload Lambda role has a policy granting `secretsmanager:GetSecretValue` on the relayer secret ARN (or resource pattern for `mnemospark/relayer-private-key`). If using a customer-managed KMS key for the secret, include `kms:Decrypt` on that key.
  - [ ] Lambda code: When settlement mode is onchain, relayer private key is obtained via `secretsmanager.get_secret_value(SecretId=os.environ["MNEMOSPARK_RELAYER_SECRET_ID"])`; key is used only in memory for signing; no log or error message contains the key or any substring of it.
  - [ ] Lambda code: No reference to `MNEMOSPARK_RELAYER_PRIVATE_KEY` from `os.environ`; all relayer-key resolution goes through Secrets Manager when onchain.
  - [ ] Template validates (`sam validate` or `aws cloudformation validate-template`). Existing tests for upload Lambda still pass (or are updated if they assumed env-based key).
  - [ ] Optional: README or template comment documents that secret `mnemospark/relayer-private-key` must exist before deployment (or optional snippet for empty secret resource).

## Task string (optional)

Work only in this repo. Implement the relayer private key secrets management per .company/infrastructure_design/secrets_management.md. (1) Template: remove MNEMOSPARK_RELAYER_PRIVATE_KEY from upload Lambda env; add IAM for secretsmanager:GetSecretValue on mnemospark/relayer-private-key; add MNEMOSPARK_RELAYER_SECRET_ID env. (2) Lambda storage-upload: when MNEMOSPARK_PAYMENT_SETTLEMENT_MODE=onchain, fetch relayer key via Secrets Manager get_secret_value; use only in memory for signing; remove any os.environ read of MNEMOSPARK_RELAYER_PRIVATE_KEY. Do not log or expose the key. Acceptance: [ ] template env + IAM; [ ] Lambda fetches from Secrets Manager; [ ] no key in env or logs; [ ] sam validate and tests pass.

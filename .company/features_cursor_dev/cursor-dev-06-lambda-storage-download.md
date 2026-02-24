# Cursor Dev: Lambda GET/POST /storage/download

**ID:** cursor-dev-06  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement the object storage Lambda for `GET /storage/download` and `POST /storage/download`: validate wallet and object key, then return a presigned GET URL for S3 (recommended for all sizes to avoid Lambda payload limits). Optionally support inline base64 for small files. Response shape per API spec §6.

## References

- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) §6
- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — download command and backend path

## Cloud Agent

- **Install (idempotent):** `pip install -r requirements.txt` (and AWS SDK).
- **Start (if needed):** None.
- **Secrets:** AWS credentials for S3.
- **Acceptance criteria (checkboxes):**
  - [ ] Lambda accepts GET (query) or POST (JSON body): `wallet_address`, `object_key`, optional `location`.
  - [ ] Validates wallet and key; resolves bucket for wallet; generates presigned GET URL for the object (short TTL).
  - [ ] Response 200 JSON: `download_url`, `object_key`, optional `expires_in_seconds` per §6 (presigned URL flow).
  - [ ] 404 or error shape per §9 if object not found.
  - [ ] Unit tests; integration test with S3 (or mocked).
  - [ ] All taggable resources (Lambda, API route, etc.) tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Implement Lambda for GET/POST /storage/download: validate wallet/key, return presigned GET URL for S3 object. Response per API spec §6. Acceptance: [ ] request params; [ ] presigned URL in response; [ ] 404/error shape; [ ] tests.

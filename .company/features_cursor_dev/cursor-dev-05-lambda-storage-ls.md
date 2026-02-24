# Cursor Dev: Lambda GET/POST /storage/ls

**ID:** cursor-dev-05  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement the object storage Lambda for `GET /storage/ls` and `POST /storage/ls`: list one object’s metadata (name + size) in the wallet’s S3 bucket. Accept `wallet_address`, `object_key`, optional `location` via query (GET) or JSON body (POST). Return JSON per API spec §7.1. Validate wallet and bucket access; return 404 if object not found.

## References

- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) §7.1
- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — ls command and backend path

## Cloud Agent

- **Install (idempotent):** `pip install -r requirements.txt` (and AWS SDK).
- **Start (if needed):** None.
- **Secrets:** AWS credentials for S3.
- **Acceptance criteria (checkboxes):**
  - [ ] Lambda accepts GET (query) or POST (JSON body): `wallet_address`, `object_key`, optional `location`.
  - [ ] Resolves bucket for wallet (e.g. mnemospark-<wallet-hash>); lists or gets object metadata for the given key.
  - [ ] Response 200 JSON: `success`, `key`, `size_bytes`, `bucket` per §7.1.
  - [ ] 404 or error shape per §9 if object or bucket not found.
  - [ ] Unit tests; integration test against S3 (or mocked).
  - [ ] All taggable resources (Lambda, API route, etc.) tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Implement Lambda for GET/POST /storage/ls: list object metadata (name + size) for wallet bucket. Request: wallet_address, object_key, optional location. Response per API spec §7.1. Acceptance: [ ] GET/POST accepted; [ ] bucket per wallet; [ ] response shape; [ ] 404/error shape; [ ] tests.

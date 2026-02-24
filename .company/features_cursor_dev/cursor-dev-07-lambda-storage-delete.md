# Cursor Dev: Lambda POST/DELETE /storage/delete

**ID:** cursor-dev-07  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement the object storage Lambda for `POST /storage/delete` and `DELETE /storage/delete`: delete the object from the wallet’s S3 bucket; if the bucket is empty after deletion, delete the bucket. Accept `wallet_address`, `object_key`, optional `location` via query or JSON body. Return JSON per API spec §7.2.

## References

- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) §7.2
- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — delete command and backend path

## Cloud Agent

- **Install (idempotent):** `pip install -r requirements.txt` (and AWS SDK).
- **Start (if needed):** None.
- **Secrets:** AWS credentials for S3.
- **Acceptance criteria (checkboxes):**
  - [ ] Lambda accepts POST or DELETE with query or JSON body: `wallet_address`, `object_key`, optional `location`.
  - [ ] Deletes object from wallet bucket; if bucket has no other objects, deletes the bucket.
  - [ ] Response 200 JSON: `success`, `key`, `bucket`, `bucket_deleted` per §7.2.
  - [ ] 404 or error shape per §9 if object or bucket not found.
  - [ ] Unit tests; integration test with S3 (or mocked).
  - [ ] All taggable resources (Lambda, API route, etc.) tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Implement Lambda for POST/DELETE /storage/delete: delete object from wallet bucket; delete bucket if empty. Response per API spec §7.2. Acceptance: [ ] request params; [ ] object deleted; [ ] bucket deleted when empty; [ ] response shape; [ ] tests.

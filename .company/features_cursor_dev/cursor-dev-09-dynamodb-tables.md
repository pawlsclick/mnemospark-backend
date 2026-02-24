# Cursor Dev: DynamoDB tables (quotes + transaction log)

**ID:** cursor-dev-09  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Add CloudFormation/SAM resources (or equivalent) for DynamoDB: (1) quotes table with TTL 1 hour for quote rows; (2) transaction log table for upload transactions. Define IAM permissions so Lambdas (price-storage, upload) can read/write as needed. No application logic in this task—tables and IAM only.

## References

- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) §4.3 (quote), §5 (upload response / txn log)
- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — quote fields, upload transaction log fields

## Cloud Agent

- **Install (idempotent):** AWS CLI; optionally SAM CLI if using SAM.
- **Start (if needed):** None.
- **Secrets (Cursor Settings → Cloud Agents → Secrets):** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` if deploying or validating.
- **Acceptance criteria (checkboxes):**
  - [ ] Quotes table defined with TTL attribute (e.g. 1h) for quote expiry; key design supports quote_id lookup.
  - [ ] Transaction log table defined for upload records (e.g. quote_id, addr, trans_id, object_id, bucket, etc.).
  - [ ] IAM role(s) or policy snippets allow price-storage Lambda to write/read quotes; upload Lambda to read quotes and write transaction log.
  - [ ] Template validates (`aws cloudformation validate-template` or `sam validate`); stack deploys or dry-run succeeds.
  - [ ] All taggable resources tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Add DynamoDB tables for mnemospark-backend: (1) quotes table with TTL 1h; (2) transaction log table for uploads. Define IAM for price-storage and upload Lambdas. Acceptance: [ ] quotes table + TTL; [ ] txn log table; [ ] IAM for both Lambdas; [ ] template validates and deploys.

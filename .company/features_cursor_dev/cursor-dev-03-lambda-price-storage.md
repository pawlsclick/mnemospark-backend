# Cursor Dev: Lambda POST /price-storage

**ID:** cursor-dev-03  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement the price-storage orchestrator Lambda for `POST /price-storage`: call the storage cost Lambda (POST /estimate/storage) and transfer cost Lambda (POST /estimate/transfer), add configurable markup, create a quote row in DynamoDB (1h TTL), and return the quote JSON per API spec §5.3. Depends on cursor-dev-01, cursor-dev-02, and cursor-dev-09 (DynamoDB quotes table).

## References

- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) §5.3
- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — price-storage workflow and quote fields

## Cloud Agent

- **Install (idempotent):** `pip install -r requirements.txt` (or project equivalent).
- **Start (if needed):** None.
- **Secrets:** AWS credentials; optionally API base URL if calling other Lambdas via HTTP.
- **Acceptance criteria (checkboxes):**
  - [ ] Lambda accepts JSON body: `wallet_address`, `object_id`, `object_id_hash`, `gb`, `provider`, `region` (all required per spec).
  - [ ] Calls storage cost and transfer cost (e.g. internal SDK or HTTP to estimate/storage and estimate/transfer); adds markup; writes quote to DynamoDB with 1h TTL.
  - [ ] Response 200 JSON includes `timestamp`, `quote_id`, `storage_price`, `addr`, `object_id`, `object_id_hash`, `object_size_gb`, `provider`, `location` per §5.3.
  - [ ] Errors (e.g. DynamoDB failure, missing params) return consistent error shape per API spec §10.
  - [ ] 402/payment headers: conform to API spec (v2 names; legacy accepted) when downstream flows use 402.
  - [ ] Unit tests; integration test with real or mocked estimate Lambdas and DynamoDB.
  - [ ] All taggable resources (Lambda, API route, etc.) tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Implement the price-storage orchestrator Lambda for POST /price-storage: call estimate/storage and estimate/transfer, add markup, write quote to DynamoDB (1h TTL), return quote JSON per API spec §5.3. Depends on 01, 02, 09. Acceptance: [ ] request/response per spec; [ ] quote in DynamoDB with TTL; [ ] error shape; [ ] tests.

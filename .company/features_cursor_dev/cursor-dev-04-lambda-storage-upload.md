# Cursor Dev: Lambda POST /storage/upload

**ID:** cursor-dev-04  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement the upload Lambda for `POST /storage/upload`: lookup quote in DynamoDB, verify payment (EIP-712/USDC on Base), then upload to S3 (bucket per wallet, client-held encryption: store ciphertext + wrapped DEK in metadata). Write transaction log to DynamoDB. Support `Idempotency-Key` header per API spec §9. Use the design pattern from `examples/object_storage_management_aws.py`. Depends on cursor-dev-09 (DynamoDB).

## References

- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) §6 (upload), §9 (idempotency)
- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — upload workflow
- [clawrouter_wallet_gen_payment_eip712.md](../clawrouter_wallet_gen_payment_eip712.md) — EIP-712 payment
- Design pattern: `examples/object_storage_management_aws.py` (bucket per wallet, encryption, ensure_bucket_exists)

## Cloud Agent

- **Install (idempotent):** `pip install -r requirements.txt` (and any crypto/AWS deps).
- **Start (if needed):** None.
- **Secrets:** AWS credentials; chain RPC or config for Base (e.g. for payment verification); recipient wallet config (e.g. `MNEMOSPARK_RECIPIENT_WALLET`).
- **Acceptance criteria (checkboxes):**
  - [ ] Lambda looks up quote by `quote_id` in DynamoDB; validates `object_id_hash` matches quote; returns 404 if quote missing or expired.
  - [ ] Payment verification: EIP-712 signature and terms; settle USDC on Base; obtain transaction id; recipient wallet from config.
  - [ ] S3: bucket per wallet (e.g. `mnemospark-<wallet-hash>`); put object with ciphertext and `wrapped-dek` in metadata; create bucket if not exists.
  - [ ] Write transaction log row to DynamoDB (quote_id, addr, trans_id, object_id, object_key, bucket, etc.); return 200 with response body per API spec §6.
  - [ ] Idempotency-Key: same key within 24h returns 200 with cached response if already completed; 409 if in progress (per §9).
  - [ ] 402/payment headers: conform to API spec §2 (v2 names; legacy accepted)—return 402 with PAYMENT-REQUIRED or x-payment-required; accept PAYMENT-SIGNATURE or x-payment on retry.
  - [ ] Unit/integration tests; error responses use common shape per §10.
  - [ ] All taggable resources (Lambda, API route, etc.) tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Implement upload Lambda for POST /storage/upload: quote lookup, EIP-712 payment verification on Base, S3 upload (bucket per wallet, client-held encryption), DynamoDB transaction log, Idempotency-Key per API spec §9. Use examples/object_storage_management_aws.py pattern. Acceptance: [ ] quote lookup + validation; [ ] payment verify + S3 upload; [ ] txn log; [ ] idempotency; [ ] tests and error shape.

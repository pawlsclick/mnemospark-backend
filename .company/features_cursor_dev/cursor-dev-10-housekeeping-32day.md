# Cursor Dev: Housekeeping job (32-day deadline)

**ID:** cursor-dev-10  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Implement a scheduled job (e.g. EventBridge rule + Lambda) that checks stored objects for payment status: if payment has not been received within **32 days** of the last due date (30-day billing interval + 2-day grace), delete the object (and bucket if empty). Recipient wallet and payment confirmation logic use config (e.g. `MNEMOSPARK_RECIPIENT_WALLET`) and transaction log or chain. Per [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) housekeeping rules.

## References

- [mnemospark_full_workflow.md](../mnemospark_full_workflow.md) — mnemospark-backend housekeeping rules (30-day billing, 32-day deadline, recipient wallet)
- [mnemospark_PRD.md](../mnemospark_PRD.md) R3 (storage fee, 32-day deadline)

## Cloud Agent

- **Install (idempotent):** `pip install -r requirements.txt` (and AWS SDK, any chain client).
- **Start (if needed):** None (scheduled Lambda).
- **Secrets:** AWS credentials; `MNEMOSPARK_RECIPIENT_WALLET`; chain RPC if checking payment on-chain.
- **Acceptance criteria (checkboxes):**
  - [ ] Scheduled trigger (e.g. EventBridge rule daily or hourly) invokes the housekeeping Lambda.
  - [ ] Lambda reads transaction log (or equivalent) to find objects with last payment due date; compares to current date; if > 32 days since last due, marks for deletion (or deletes).
  - [ ] Deletion: remove object from S3; delete bucket if empty; update or remove transaction record as needed.
  - [ ] Recipient wallet from env (e.g. `MNEMOSPARK_RECIPIENT_WALLET`); payment confirmation logic documented or implemented (on-chain check or ledger).
  - [ ] Unit tests; optional integration test with mocked data.
  - [ ] All taggable resources (Lambda, EventBridge rule, etc.) tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Implement housekeeping scheduled job for mnemospark-backend: EventBridge + Lambda that checks payment per object; if not paid within 32 days of last due date, delete object and bucket if empty. Use MNEMOSPARK_RECIPIENT_WALLET. Ref: full_workflow housekeeping. Acceptance: [ ] scheduled trigger; [ ] 32-day check; [ ] delete object/bucket; [ ] recipient wallet from config; [ ] tests.

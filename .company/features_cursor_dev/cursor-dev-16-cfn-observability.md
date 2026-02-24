# Cursor Dev: CloudFormation — Observability

**ID:** cursor-dev-16  
**Repo:** mnemospark-backend  
**Rough size:** One Cloud Agent run

**Workspace for Cloud Agent:** Work only in **this repo** (the repo you were started in). This repo is mnemospark-backend. Backend features (01–10, 15–17) and design patterns live in this repo (e.g. `examples/s3-cost-estimate-api`). Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository; all code and references are in this repo and `.company/`.

## Scope

Add a **CloudFormation** template (or extend existing) for **observability**: CloudWatch log group(s) for API Gateway access logging and Lambda execution; CloudWatch alarms for 4xx, 5xx, throttle, and latency. Optional: CloudTrail for API and account activity. Per [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md) § Logging and monitoring. Depends on cursor-dev-08 (API Gateway and Lambdas).

## References

- [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md) — Logging and monitoring (API Gateway access logging, Lambda logs, CloudWatch alarms, CloudTrail)

## Cloud Agent

- **Install (idempotent):** AWS CLI.
- **Start (if needed):** None.
- **Secrets (Cursor Settings → Cloud Agents → Secrets):** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`.
- **Acceptance criteria (checkboxes):**
  - [ ] CloudFormation defines CloudWatch log group(s) for API Gateway access logs and/or Lambda execution logs; API Gateway stage configured to write access logs to the log group (or doc how to enable).
  - [ ] At least one CloudWatch alarm for API Gateway or Lambda: e.g. 4xx count, 5xx count, throttle count, or latency (metric and threshold defined).
  - [ ] Optional: CloudTrail or documentation for enabling it for API and account actions.
  - [ ] Template validates; stack deploys or change-set succeeds (or README with deploy steps).
  - [ ] All taggable resources tagged with `Project: mnemospark` (or `Application: mnemospark`).

## Task string (optional)

Work only in this repo; do not use BlockRun/ClawRouter or any other repo. Before implementing, read .company/features_cursor_dev/AWS_DOCS_REFERENCES.md and use the listed AWS docs for CloudFormation/SAM syntax. Add CloudFormation for observability: CloudWatch log groups (API access + Lambda), alarms for 4xx/5xx/throttle/latency. Optional CloudTrail. Ref: infrastructure_design/internet_facing_API.md § Logging and monitoring. Depends on 08. Acceptance: [ ] log groups; [ ] alarms; [ ] template validates and deploys.

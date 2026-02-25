# mnemospark – Product Requirements Document (PRD)

**Version:** 2.3  
**Last updated:** February 2026  
**Source:** [mnemospark_product_spec_v3.md](./mnemospark_product_spec_v3.md)  
**Audience:** Product, Engineering, Leadership, Antfarm feature development

**Changelog (v2.3):**

- **Secrets management:** Relayer private key (Base wallet) must be stored in **AWS Secrets Manager** only—never in environment variables, CloudFormation parameters, or code. See [infrastructure_design/secrets_management.md](./infrastructure_design/secrets_management.md). Implemented via cursor-dev-18 (Secrets Manager for relayer key). R8c added; PRD → Feature mapping and References updated.

**Changelog (v2.2):**

- **References:** Added [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) and [infrastructure_design/internet_facing_API.md](./infrastructure_design/internet_facing_API.md).
- **Idempotency:** Resolved from API spec §8 (optional key, 24h TTL for upload).
- **R3:** 30/32-day billing and recipient wallet config stated; backend housekeeping aligned with full workflow.
- **Backend auth:** API key (proxy-to-backend) and deployment security reference added in R8b.
- **Open question 1 (idempotency):** Resolved; open question 2 (activity log): resolved to Option A.
- **R8:** Object lifecycle log (`object.log`) vs audit log (`logs/`) clarified.

**Changelog (v2):**

- Aligned with product spec **v3**: single AWS account, **one S3 bucket per wallet** (no AWS Organizations or sub-accounts).
- **Phased MVP:** Phase 1 = S3 + SSE-S3/SSE-KMS only (no client-held key); Phase 2 = client-held envelope encryption (KEK/DEK).
- Tenant model: **Wallet = tenant**; bucket creation in same account on first verified payment.
- This PRD drives **Antfarm** feature-dev task strings and acceptance criteria; requirements are the contract for planner → implement → verify.

**Changelog (v2.1):**

- **MVP encryption = Phase 2 only:** No Phase 1 (SSE-S3/SSE-KMS). Ship with **client-held envelope encryption** (KEK/DEK) from day one; key store at `~/.openclaw/mnemospark/keys/`. See [mnemospark_full_workflow.md](./mnemospark_full_workflow.md) and [spec_feedback_for_sr_engineer.md](./features/spec_feedback_for_sr_engineer.md).
- **Get storage usage:** Removed from MVP; `/cloud ls` is sufficient. No separate “get storage usage” endpoint in scope.

---

## Problem

### User problem

OpenClaw agents need **persistent, sovereign storage** for state, memories, and artifacts, but today:

- **No account/session setup required for paid API access** is a first-class benefit of x402; mnemospark provides paid storage access without sign-up or OAuth.
- Storage typically requires **human-managed API keys** (e.g. S3 credentials), which breaks autonomous agent operation.
- There is **no standard way** for agents to **pay for their own** storage so that cost is aligned with usage and no central key tops up on behalf of many agents.
- **Data sovereignty** (where data lives) and **metering** (pay per sync and per storage) are not unified in one product for the OpenClaw ecosystem.

### Business problem

- Without a dedicated storage product that uses **payment-as-authentication**, OpenClaw and its agents depend on ad-hoc storage and keys, limiting scale and operator trust.
- Revenue opportunity: **metered storage** (activity + monthly fee) with a clear **x402** flow can differentiate the platform and align revenue with usage.

### Evidence

- Product spec v3 describes storage orchestration with **one AWS account**, **one S3 bucket per wallet**. MVP uses **client-held envelope encryption only** (KEK/DEK). OpenClaw plugin pattern and wallet/x402 flow exist in codebase.
- Spec resolves tenant model (no Orgs; wallet = tenant; bucket per wallet), pricing (BCM + GetCostForecast + markup), and MVP scope (S3, 2–3 regions) as the basis for build.

---

## Goals and success metrics

### Goals

1. **Ship MVP:** Storage orchestration for OpenClaw agents using **x402 payment-as-authentication**, with **AWS S3** in **2–3 regions**, so agents can pay per sync and per month for storage without API keys. **One AWS account**; **one S3 bucket per wallet** (per region). Encryption: **client-held envelope encryption only** (KEK/DEK, key store at `~/.openclaw/mnemospark/keys/`) — “their data, their key”; no Phase 1 (SSE-S3/SSE-KMS).
2. **Prove the model:** Per-request 402 and on-chain verification before access; payment triggers **bucket creation for wallet** (if needed) in the same account; usage and billing from **AWS APIs only** (no internal ledger for GB stored).
3. **Integrate cleanly:** Install as OpenClaw plugin; same install/use pattern as prior plugin (config, wallet, commands, gateway lifecycle). Commands: `/wallet`, `/cloud` (and subcommands per [mnemospark_full_workflow.md](./mnemospark_full_workflow.md)).

**Interoperability (x402):**

- Works with **x402 v2 header names** (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`); maintains **backward compatibility** where practical (legacy headers accepted).
- **Agent autonomy + pay-per-use:** No subscription or account-centric flows; per-request payment and on-chain verification only.

### Success metrics

| Metric                    | Target                                                                                                          | Measurement               |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------- |
| **Payment-before-access** | 100% of storage operations require verified on-chain payment before any S3 call                                 | Gateway logic + audit/log |
| **Quote accuracy**        | Activity and storage quotes match BCM/GetCostForecast + configured markup within defined tolerance              | Unit/integration tests    |
| **Time to first store**   | New wallet: first successful upload within &lt; 5 min (including bucket provisioning) after funding             | E2E test / manual         |
| **Plugin adoption**       | Plugin installs and loads without error; gateway starts/stops with OpenClaw                                     | Install test matrix       |
| **Retry safety**          | Clients can retry with idempotency key without double charge or duplicate object (once idempotency is resolved) | API tests                 |

---

## Users and use cases

### Primary users

1. **OpenClaw instance operator / user**
   - Installs mnemospark plugin, funds wallet, uses `/wallet` and `/storage`; expects storage to “just work” when the agent or user triggers sync.

2. **OpenClaw agent (main or sub-agent)**
   - Jobs: persist state, memories, artifacts; choose region for data; pay per upload/download/list and monthly for storage. No human in the loop for credentials.

3. **Developer / integrator**
   - Builds skills or tools that call the storage REST API; needs clear 402 contract, payment header, and idempotency behavior.

### Primary use cases

| Use case                            | Actor          | Flow                                                                                                          |
| ----------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------- |
| **First-time store**                | Agent          | Request upload → 402 → fund/sign → verify → ensure bucket for wallet exists (create if needed) → upload → 200 |
| **Subsequent upload/download/list** | Agent          | Request → 402 → pay (if not cached) → verify → orchestrator → S3 (bucket per wallet, key by agent) → 200      |
| **Monthly storage fee**             | System / agent | GetCostForecast + markup → one x402 per month per wallet for hosting                                          |
| **Install and configure**           | User           | Install plugin → config (or defaults) → wallet path → gateway runs with OpenClaw                              |
| **Check balance and list storage**  | User / agent   | `/wallet` (balance), `/cloud ls` (list objects in bucket; no separate “get storage usage” in MVP)             |

---

## Requirements

### Must-have (MVP — Phase 2 encryption only)

- **R1.** **x402 payment-as-authentication:** All storage API calls go through an x402 gateway. Gateway returns 402 with payment options (amount from BCM quote + markup). After client retries with payment, gateway verifies **on-chain** before performing any S3 operation or triggering bucket provisioning.
- **R2.** **Activity fee:** Quote via **BCM Pricing Calculator API** for S3 (upload, download, list/egress); apply configurable **markup**; expose amount in 402 body; charge OpenClaw wallet per request after verification.
- **R3.** **Storage fee:** Use **GetCostForecast** for forecasted storage cost; apply markup; charge OpenClaw wallet **once per month** via x402 for storage hosting. Backend expects payment within **32 days** of last due date (30-day billing interval + 2-day grace); if not confirmed by the 32-day deadline, the stored object is deleted. Recipient wallet is configured via deployment (e.g. `MNEMOSPARK_RECIPIENT_WALLET`; canonical address in [mnemospark_full_workflow.md](./mnemospark_full_workflow.md)).
- **R4.** **Storage backend (S3):** Single provider interface: create bucket (or use existing), PUT, GET, LIST, delete, metadata. Implementation: **AWS S3** via **@aws-sdk/client-s3** (v3), **IAM role or user** in **single AWS account**. **One bucket per wallet** (per region as configured). Within bucket, key data by **wallet + agent** (e.g. `agent=<agent-id>/...`).
- **R5.** **Orchestrator:** Given region, wallet id, agent id, key (and body for PUT), select **bucket (per wallet)** and storage class; call S3 backend. No payment or pricing in orchestrator.
- **R6.** **Tenant model:** **Single AWS account.** **Wallet = storage tenant.** **One S3 bucket per wallet** (per region), named `mnemospark-<wallet-id-hash>`. Payment verification triggers **bucket creation for wallet** (if needed) in the same account; no AWS Organizations or sub-accounts.
- **R7.** **Agent-facing API:** REST: Upload object, Download object, List (prefix/object). All require per-request x402. No separate “get storage usage” endpoint in MVP; `/cloud ls` is sufficient. Idempotency for upload per [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) §8 (optional key, 24h TTL). Full API contract (auth, payloads, errors) in [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) and [mnemospark_full_workflow.md](./mnemospark_full_workflow.md).
- **R8.** **OpenClaw integration:** Plugin installable via OpenClaw plugin system; config under `openclaw.json` or `~/.openclaw/mnemospark/`; wallet at `~/.openclaw/blockrun/wallet.key` if present, else `~/.openclaw/mnemospark/key/wallet.key`; object lifecycle log per workflow at `~/.openclaw/mnemospark/object.log`; audit/activity log at `~/.openclaw/mnemospark/logs/`; commands **`/wallet`, `/cloud`** (and subcommands per [mnemospark_full_workflow.md](./mnemospark_full_workflow.md)); gateway starts when OpenClaw gateway runs, stops on service `stop()`. **mnemospark proxy port: 7120** (configurable via `MNEMOSPARK_PROXY_PORT`).
- **R8b.** **Backend API architecture:** mnemospark-backend exposes **one internet-facing REST API** (API Gateway). Requests are routed **by path** to **specific Lambda functions**; each Lambda has a single responsibility and least-privilege IAM. Backend is secured by **API key** (proxy/server-to-backend); details in [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) §1. Path-to-Lambda mapping and full API contract: [mnemospark_full_workflow.md](./mnemospark_full_workflow.md) § mnemospark-backend API architecture and [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) (e.g. `POST /estimate/storage` → S3 storage cost Lambda; `POST /price-storage` → price-storage orchestrator Lambda; `POST /storage/upload`, `GET /storage/ls`, etc. → object storage Lambda). Deployment should follow [infrastructure_design/internet_facing_API.md](./infrastructure_design/internet_facing_API.md) for the public API.
- **R8c.** **Secrets management (relayer key):** The **Base wallet relayer private key** used for on-chain USDC settlement must be stored in **AWS Secrets Manager** only (e.g. secret ID `mnemospark/relayer-private-key`). It must not live in Lambda environment variables, CloudFormation/SAM parameters, or application code. The upload Lambda reads it at runtime via `secretsmanager:GetSecretValue`; use only in memory for signing; never log or expose it. See [infrastructure_design/secrets_management.md](./infrastructure_design/secrets_management.md).
- **R9.** **Usage source of truth:** **No internal ledger** for GB stored. Use **AWS APIs only** (S3, Cost Explorer/GetCostForecast) for usage and billing.
- **R10.** **MVP scope:** AWS S3 only (no Glacier); 2–3 regions; no region premium; cost + markup only.
- **R11.** **Encryption (MVP):** **Client-held envelope encryption only** (KEK/DEK) per `mvp_option_aws_client_encryption.md`: client stores KEK in key store (file under `~/.openclaw/mnemospark/keys/`); client encrypts payload with DEK, wraps DEK with KEK; backend stores only ciphertext + wrapped_DEK. Goal: “their data, their key.” No Phase 1 (SSE-S3/SSE-KMS) in scope.

### Nice-to-have (MVP or immediately post-MVP)

- **R12.** Idempotency key **required** for all mutating calls (stricter contract).
- **R13.** Lightweight **activity log** (e.g. JSONL under `~/.openclaw/mnemospark/logs/`) for audit/support (timestamp, request type, wallet, amount, success/failure).
- **R14.** Agent-facing docs: how to fund wallet, call storage API, interpret 402, activity vs storage fees, and key management.

### Out of scope (MVP)

- **S3 Glacier** (restore, archive tiers).
- Other storage backends (GCS, Azure Blob, IPFS).
- **Region premium**; **pre-paid balance**; **off-chain ledger**.
- Full CRR/SRR and Multi-Region Access Points (can be phased later).
- **AWS Organizations** and sub-account–based tenant isolation.

---

## Success metrics (detailed)

- **Functional:** Every storage operation (upload, download, list) succeeds only after on-chain payment verification; monthly storage fee charged once per wallet per month.
- **Operational:** Bucket provisioning for new wallet (create-if-not-exists in single account) completes on first verified payment; Orchestrator + S3 backend use correct region and **bucket per wallet**; objects keyed by agent within bucket.
- **Experience:** Clear 402 response and retry flow; no double charge when idempotency is used (once specified); plugin install and gateway lifecycle work as in product spec v3.

---

## Risks, dependencies, and open questions

### Risks

| Risk                                                  | Mitigation                                                                                                                |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| BCM/GetCostForecast API limits or latency             | Use with backoff; return 503 or “quote unavailable” if APIs fail; document rate limits.                                   |
| Bucket creation (single account) slow or rate-limited | Create-if-not-exists with retry; gateway returns 503 and asks client to retry; idempotency avoids double charge on retry. |
| Single-account blast radius                           | IAM and bucket policies enforce per-wallet isolation; no cross-wallet access.                                             |
| Idempotency for upload                                | Contract defined in API spec §8; implement and verify; extend to other mutating ops if needed.                            |

### Dependencies

- **OpenClaw plugin API** (commands, service, config schema).
- **AWS:** S3, BCM Pricing Calculator API, Cost Explorer GetCostForecast; **IAM role or user in single account** (no Organizations or CloudFormation for tenant isolation).
- **Existing codebase:** x402, auth, balance, payment-cache, config, logger; proxy-style HTTP and 402 retry flow (to be replaced with storage gateway).

### Open questions

1. **Idempotency:** Contract defined in [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) §8 — optional header, 24h TTL for upload. Required vs optional for other mutating operations TBD.
2. **Activity log:** Resolved — Option A. Lightweight JSONL under `~/.openclaw/mnemospark/logs/` for audit/support (per product spec v3 and round 3).

---

## PRD → Feature mapping

| PRD requirement / area                               | Feature(s)                                                               |
| ---------------------------------------------------- | ------------------------------------------------------------------------ |
| R1 (x402 payment-as-auth)                            | Feature 01 (x402 Storage Gateway), Feature 06 (Agent-Facing Storage API) |
| R2 (Activity fee)                                    | Feature 01, Feature 03 (Pricing Module)                                  |
| R3 (Storage fee)                                     | Feature 01, Feature 03                                                   |
| R4 (S3 backend)                                      | Feature 02 (S3 Storage Backend)                                          |
| R5 (Orchestrator)                                    | Feature 04 (Orchestrator)                                                |
| R6 (Tenant model: bucket-per-wallet, single account) | Feature 05 (Bucket-per-wallet provisioning)                              |
| R7 (Agent-facing API)                                | Feature 06                                                               |
| R8 (OpenClaw integration)                            | Feature 07 (OpenClaw Plugin Integration)                                 |
| R8c (Secrets: relayer key in Secrets Manager)        | cursor-dev-18 (Secrets Manager for relayer private key)                  |
| R9 (Usage source of truth)                           | Feature 02, Feature 03                                                   |
| R10 (MVP scope)                                      | All features                                                             |
| R11 (Encryption: client-held KEK/DEK only)           | Feature 02, Encryption module (KEK/DEK, key store)                       |
| R12–R14 (Nice-to-have)                               | Feature 01, 06, 07; spec feedback doc                                    |
| Open questions                                       | spec_feedback_for_sr_engineer.md                                         |

---

## Antfarm: PRD as contract for feature development

This PRD is the **source of truth** for Antfarm feature-dev workflows. Use it to:

- **Task strings:** Each feature (01–07) should be implementable via a single `feature-dev` task string (or a small set of stories). The task string must include: what to build, key constraints from this PRD, and **acceptance criteria** drawn from the requirements above so the verifier can gate completion.
- **Acceptance criteria:** Requirements R1–R11 are the basis for verifier checkboxes; avoid vague criteria to reduce token waste and retry loops.
- **Scoping:** MVP = R1–R11 (client-held encryption only; no Phase 1 SSE-S3/SSE-KMS).
- **Hand-off:** When generating task strings for Antfarm, reference this PRD version (v2.2) and the product spec v3; keep context minimal and structured (e.g. REPO, BRANCH, STORIES_JSON, requirement IDs). API contract and acceptance criteria can reference [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) where applicable.

---

## Appendix: Backend path-based routing

The backend exposes **one internet-facing REST API** (API Gateway). API Gateway routes by path to a specific Lambda; each Lambda has a single responsibility and least-privilege IAM.

| Client command / use | Method and path                                     | Lambda responsibility                                                                   |
| -------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------- |
| price-storage        | `POST /price-storage`                               | Price-storage Lambda: storage cost + transfer cost + markup + DynamoDB quote (1h TTL).  |
| (building block)     | `POST /estimate/storage`                            | S3 storage cost Lambda: BCM only.                                                       |
| (building block)     | `POST /estimate/transfer`                           | Data transfer cost Lambda: BCM only.                                                    |
| upload               | `POST /storage/upload`                              | Upload Lambda: quote lookup, payment verification, S3 upload, DynamoDB transaction log. |
| ls                   | `GET /storage/ls` or `POST /storage/ls`             | Object storage Lambda: list object metadata.                                            |
| download             | `GET /storage/download` or `POST /storage/download` | Object storage Lambda: get object, decrypt, stream/return.                              |
| delete               | `POST /storage/delete` or `DELETE /storage/delete`  | Object storage Lambda: delete object (and bucket if empty).                             |

See [mnemospark_full_workflow.md](./mnemospark_full_workflow.md) for full workflow and path details.

---

## Appendix: References

- **Product spec v3:** [mnemospark_product_spec_v3.md](./mnemospark_product_spec_v3.md)
- **Full workflow:** [mnemospark_full_workflow.md](./mnemospark_full_workflow.md)
- **Backend API spec:** [mnemospark_backend_api_spec.md](./mnemospark_backend_api_spec.md) — REST API contract (paths, API key auth, request/response, idempotency, errors, presigned URL flows).
- **Infrastructure (security):** [infrastructure_design/internet_facing_API.md](./infrastructure_design/internet_facing_API.md) — AWS security and hardening for the backend API (API Gateway, WAF, throttling, etc.).
- **Secrets management:** [infrastructure_design/secrets_management.md](./infrastructure_design/secrets_management.md) — Relayer private key in AWS Secrets Manager only; no env vars or parameters for the key.
- **Feature specs:** [.company/features/README.md](./features/README.md)
- **Cursor Cloud Agent features:** [.company/features_cursor_dev/README.md](./features_cursor_dev/README.md) — cursor-dev-01 through cursor-dev-18 (backend + client micro-features).
- **Spec feedback (sr. engineer):** [.company/features/spec_feedback_for_sr_engineer.md](./features/spec_feedback_for_sr_engineer.md)
- **Client-held encryption (Phase 2):** [.company/archive/mvp_option_aws_client_encryption.md](./archive/mvp_option_aws_client_encryption.md)

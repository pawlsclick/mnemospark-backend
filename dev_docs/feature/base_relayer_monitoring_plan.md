# Plan: Base relayer wallet monitoring

**Branch:** `feat/base-relayer-monitoring`  
**Spec:** [base_relayer_monitoring_spec.md](./base_relayer_monitoring_spec.md)  
**Goal:** Avoid the relayer running out of ETH for gas; persist and query relayer spend, volume, and runway.

_Use this file as the Cursor implementation plan (tracked in git; `.cursor/` is ignored in this repo)._

---

## 1. Codebase review vs spec

### What already exists

| Area | Today | Spec expectation |
|------|--------|-------------------|
| On-chain settlement | `_onchain_settle_payment` in `services/storage-upload/app.py` uses **Web3.py**, sends raw tx, **`wait_for_transaction_receipt`** (sync), returns tx hash hex | “Lambda A writes metadata”; viem examples |
| Relayer key | `MNEMOSPARK_RELAYER_SECRET_ID` → Secrets Manager; `_resolve_relayer_private_key()` | Same secret story fits |
| Base RPC | `MNEMOSPARK_BASE_RPC_URL` on **PaymentSettleFunction** only in `template.yaml` | Dedicated RPC in prod |
| DynamoDB | **`UploadTransactionLogTable`**: keys `quote_id` + `trans_id`; stores `trans_id` (tx hash for onchain), no gas fields | **`RelayerTransactions` / `RelayerStats` / `RelayerHealth`** (new) |
| Scheduled Lambda pattern | `StorageHousekeepingFunction` + `AWS::Events::Rule` in `template.yaml` | EventBridge schedules for monitor |

### Gaps and mismatches

1. **Runtime / RPC client:** Spec shows **TypeScript + viem**. This repo is **Python 3.13** Lambdas; settlement already uses **web3.py**. Implementation should use **`eth_getTransactionReceipt`** / **`eth_getBalance`** via the same stack (or thin wrapper), unless you explicitly add a Node Lambda (not recommended for one feature).
2. **No “pending” relayer queue today:** Settlement **blocks until receipt** and only returns on success. There is **nothing in DynamoDB** with `status: pending` for relayer txs unless we **add** a write-before-broadcast or a **reconciliation** path for edge cases (dropped RPC, partial failures, future async submit).
3. **“Lambda A writes transaction metadata”:** `_write_transaction_log` records **business** upload/payment fields, **not** `gasUsed`, `effectiveGasPrice`, or `WALLET#…` keys from the spec.
4. **Two call paths into settlement:** `verify_and_settle_payment` is used from **storage upload** and from **`payment-settle`** (dynamic import of `storage-upload` payment core). Any relayer instrumentation must cover **both** paths (shared helper).
5. **Template vs code:** **`StorageUploadFunction`** does **not** declare `MNEMOSPARK_BASE_RPC_URL` or `MNEMOSPARK_RELAYER_SECRET_ID` in `template.yaml`, while **`PaymentSettleFunction`** does. If upload is supposed to run **onchain** settlement in deployed stacks, that may be a **pre-existing config gap**; worth confirming in ops.

---

## 2. Proposed target architecture (aligned with repo)

- **Lambda A (extend existing):** After a successful on-chain settlement (when you already hold the **receipt**), write or update one row in **`RelayerTransactions`** (and optionally enqueue nothing if you only persist **confirmed** rows in v1).
- **Lambda B (new):** `services/base-relayer-monitor` (name TBD), triggered by **EventBridge**:
  - **Reconcile:** Query items that still need receipt data (if any); `eth_getTransactionReceipt` + idempotent `UpdateItem`.
  - **Stats / health:** Recompute **7d** (and spec’s daily/weekly/monthly) aggregates into **`RelayerStats`**, **`RelayerHealth`**; `eth_getBalance` for runway.
- **Infra:** New DynamoDB tables + IAM role + **one or two** schedule rules (fast reconcile vs slower stats), same style as `StorageHousekeepingScheduleRule`.

**Private key:** Monitor Lambda should **not** need the relayer private key. Prefer **`MNEMOSPARK_RELAYER_WALLET_ADDRESS`** (or derive once at deploy from the secret into **SSM Parameter** / stack output) for `eth_getBalance` and partition keys.

---

## 3. DynamoDB design (from spec, minor clarifications)

Implement three tables as in the spec, with these implementation notes:

- **`RelayerTransactions`**
  - PK/SK as specified (`WALLET#<address>`, `TX#<timestamp>#<txHash>`).
  - Ensure **idempotent** updates (same hash + confirmed fields) via conditional or merge pattern.
  - For **v1 “sync settlement”**, most rows can be written **once** in **success** state with gas fields populated from the receipt already in memory.
- **`RelayerStats`**
  - PK encodes period; document concrete `PERIOD` string patterns (e.g. `DAY#YYYY-MM-DD`, `WEEK#…`, `MONTH#…`) in code constants.
  - Large integers: keep **wei** as **decimal strings** (Python `int` → `str`) to avoid float drift; use `int` math in Lambda.
- **`RelayerHealth`**
  - Single `HEALTH#LATEST` per wallet as spec; overwrite each stats run.

**Optional later:** GSI if you need queries beyond PK (not required for single relayer + `Query` on PK).

---

## 4. Implementation phases

### Phase A — Infrastructure (`template.yaml`)

- Add **`RelayerTransactionsTable`**, **`RelayerStatsTable`**, **`RelayerHealthTable`** (namespaced with `${AWS::StackName}-…`).
- Add **`BaseRelayerMonitorFunction`** + **`BaseRelayerMonitorLambdaRole`**:
  - `GetItem` / `PutItem` / `UpdateItem` / `Query` (as needed) on the three tables.
  - No Secrets Manager **unless** you choose to read address from secret (prefer env/SSM).
  - Outbound HTTPS to Base RPC (no extra IAM for public RPC; if VPC endpoint needed, follow existing patterns).
- Add **EventBridge rules** (parameters for expressions, defaults e.g. `rate(5 minutes)` reconcile, `rate(1 hour)` stats — tune with you).
- Parameters: `BaseRpcUrl` already exists; add **`RelayerWalletAddress`** (or document derivation).

### Phase B — Instrument settlement (Lambda A)

- Extract a small **shared module** under `services/common/` (e.g. `relayer_ledger.py`) to avoid duplicating Dynamo writes between packages:
  - `record_relayer_transaction(...)` using receipt fields: `gasUsed`, `effectiveGasPrice` (Base legacy tx uses gas price; if you move to EIP-1559 later, map **`effectiveGasPrice`** from receipt consistently).
  - Compute `feePaidWei = gasUsed * effectiveGasPrice`.
- Call from **`_onchain_settle_payment`** immediately after successful receipt (both code paths funnel here).
- **Mock mode:** Either skip ledger writes or write with `status` / source tag indicating non-chain (product decision).

### Phase C — Monitor Lambda (Lambda B)

- Load wallet address + RPC URL from env.
- **Pending reconciliation loop:** `Query` `RelayerTransactions` for wallet PK with `FilterExpression` on `status = pending` (acceptable at low volume) or maintain a small **GSI** if volume grows.
- **Stats:** Scan or query last 7 days of txs for wallet (depends on SK sort order — ensure timestamp in SK supports range queries) → compute averages → write **`RelayerStats`** + **`RelayerHealth`**.
- **Runway:** Implement spec formulas; guard **divide-by-zero** when `avgTxPerDay_7d` or fee average is 0 → treat as “unknown” status or OK with large runway.
- **Retries:** boto3 + web3 with timeouts/backoff consistent with `_onchain_settle_payment` (`request_kwargs={"timeout": 20}`).

### Phase D — Observability & alerts

- **Structured logs** for `status` transitions (ok / warning / critical).
- **Emit alert if needed:** Wire to **SNS topic** (new resource + opt-in subscription) or **CloudWatch alarm** on a custom metric published from the monitor — pick one pattern and document in `docs/`.

### Phase E — Tests

- **Unit:** Fee math, runway edge cases, Dynamo idempotency (moto or stubbed clients).
- **Integration (optional):** Mock RPC responses for receipt/balance.

### Phase F — Documentation

- Update **`docs/openapi.yaml`** only if you add **read APIs** for health (spec does not require a public API; internal/ops-only may stay Lambda+CLI).
- Short **`docs/`** note for operators: RPC URL, alarm subscription, how to read `RelayerHealth`.

---

## 5. Open questions (for your review)

1. **Spec vs stack:** Do you want to **amend the spec** to say **Python + web3.py** (and link Web3 receipt/balance docs) instead of viem, so future readers do not assume a second runtime?
2. **Alerts:** Preferred channel — **SNS email**, **Slack**, **PagerDuty**, or **CloudWatch alarm only**? Who subscribes in prod?
3. **Relayer address:** OK to add **`MNEMOSPARK_RELAYER_WALLET_ADDRESS`** as a **CloudFormation parameter** (set at deploy), or should ops **derive from the existing secret** at deploy time (no new param)?
4. **Pending txs:** For v1, is **write-on-success-only** (no pending state) acceptable, plus reconciliation only for **future** async or manual “pending” rows? Or do you require **write at broadcast** + monitor for **every** tx?
5. **Historical backfill:** Should the first deploy **scan `UploadTransactionLog`** (and/or **payment ledger** fields) for past `trans_id` values and backfill **`RelayerTransactions`** via RPC (rate-limited), or start **from deploy forward** only?
6. **Storage upload onchain:** Is production settlement **only** via **`POST /payment/settle`**, or must **`POST /storage/upload`** also run onchain? If both, should we **fix `template.yaml`** to give **StorageUploadFunction** the same RPC + secret env and IAM as payment settle?
7. **Multi-wallet:** Spec defers multi-wallet; confirm **single relayer** for the next 6–12 months so PK design stays `WALLET#<one address>` only.

---

## 6. Success criteria (review checklist)

- [ ] Relayer ETH balance and **estimated days of runway** stored in **`RelayerHealth`** and visible to ops (table read or admin path).
- [ ] Per-tx **fee paid** and **gas used** persisted for on-chain settlements.
- [ ] **Daily / weekly / monthly** counts and fee totals in **`RelayerStats`** (exact key shapes documented in code).
- [ ] **Warning / critical** when runway drops below thresholds (3d / 1d).
- [ ] **Idempotent** Dynamo writes; monitor safe to run on overlapping schedules.
- [ ] **ruff** + **pytest** green; **`sam validate`** passes.

---

## 7. Suggested follow-up after approval

1. Lock answers to **§5**.  
2. Implement Phase A → B → C in order; ship alerts (D) once health row is stable.  
3. Optional backfill script or one-time monitor invocation if **§5.5** is “yes.”

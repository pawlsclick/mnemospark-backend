# Plan: Base relayer wallet monitoring

**Branch:** `feat/base-relayer-monitoring`  
**Spec:** [base_relayer_monitoring_spec.md](./base_relayer_monitoring_spec.md)  
**Goal:** Avoid the relayer running out of ETH for gas; persist and query relayer spend, volume, and runway.

_Use this file as the Cursor implementation plan (tracked in git; `.cursor/` is ignored in this repo)._

---

## 0. Locked product / engineering decisions

| Topic | Decision |
|--------|-----------|
| Stack & patterns | **Python 3.13 + Web3.py** only; **no viem / Node**; **minimize** changes and avoid new architectural patterns unless needed. **Spec amended** accordingly. |
| Alerts | **SNS → email** to **alerts@mnemospark.ai**. Implement `AWS::SNS::Topic` + `AWS::SNS::Subscription` (`Protocol: email`, `Endpoint: alerts@mnemospark.ai`). Monitor Lambda `Publish` to topic on **warning/critical** (and optionally OK recovery). **Note:** the inbox must **confirm** the SNS subscription once via AWS’s confirmation email. |
| Relayer address | **`MNEMOSPARK_RELAYER_WALLET_ADDRESS`** set from a new CloudFormation **parameter** (e.g. `RelayerWalletAddress`) passed into the **monitor** Lambda (and any other function that needs the literal address for Dynamo keys). See **§0.1** for where to type the value. |
| On-chain entry point | **All on-chain settlement is centralized on `POST /payment/settle`**. Relayer ledger instrumentation should align with that operational model (see **§0.2**). Do **not** expand `StorageUploadFunction` with RPC/relayer secrets for on-chain work as part of this feature. |
| Wallet count | **Single** relayer wallet; PK design `WALLET#<one address>` only. |

### 0.1 Where to set `MNEMOSPARK_RELAYER_WALLET_ADDRESS`

1. **`template.yaml`** — add a parameter, for example:

   ```yaml
   RelayerWalletAddress:
     Type: String
     Description: Checksum or lower-hex Base address for the relayer (no private key)
   ```

   Wire it to the monitor function:

   ```yaml
   MNEMOSPARK_RELAYER_WALLET_ADDRESS: !Ref RelayerWalletAddress
   ```

2. **Deploy time** — pass the address when you deploy, for example:

   ```bash
   sam deploy --parameter-overrides RelayerWalletAddress=0xYourRelayerAddress...
   ```

   Or set **`RelayerWalletAddress`** in **`samconfig.toml`** / CI **`parameter_overrides`** for each environment (dev/staging/prod).

3. **Value** — use the same **0x…** address as `Account.from_key(relayer_private_key).address` for the key stored in Secrets Manager (checksum or lowercase hex both work if the code normalizes).

### 0.2 Centralizing on `POST /payment/settle`

Settlement logic still lives in shared Python (`verify_and_settle_payment` → `_onchain_settle_payment`). **Operationally**, clients should perform on-chain payment **only** through **`POST /payment/settle`** so relayer activity is one place.

- **Instrumentation:** Record **`RelayerTransactions`** when `_onchain_settle_payment` completes successfully (receipt in hand). That path is used whenever the payment core runs in **onchain** mode—today both upload and payment-settle can call it; **product routing** should favor **payment/settle** only for on-chain.
- **Not in scope for this feature:** Ripping out or hard-disabling on-chain from **`/storage/upload`** in code; if you want that enforced in API behavior, treat it as a **follow-up** change.

---

## 1. Decisions on pending writes & backfill (Q4 & Q5)

These were open choices; below is the **recommended default** aligned with *minimal change* and **how the code works today**.

### Q4 — Pending transactions vs write-on-success-only

**What we’re choosing:** **Write-on-success-only** for v1: when `_onchain_settle_payment` has a **successful** receipt, write one **confirmed** row to **`RelayerTransactions`** (gas, fee, hashes). Do **not** add a “pending at broadcast” row or a mandatory 5-minute reconcile loop for the common case.

**Why the spec mentioned “pending”:** That pattern fits **async** submission (send tx, return immediately, later reconcile). Your Lambdas **already** `wait_for_transaction_receipt` before returning; if that succeeds, there is nothing to “reconcile” for gas accounting unless the process crashed in an extremely narrow window.

**Tradeoff:** Simpler, fewer writes, monitor focuses on **aggregates + balance + alerts**. You **lose** automatic Dynamo tracking for txs that were broadcast but the Lambda died before a receipt (rare if you keep synchronous wait). If you later go async, add **pending** rows + reconcile.

**Optional:** Keep a **lightweight** reconcile path in the monitor (query `status = pending`) for **future** use or manual repair rows—can be empty in v1.

### Q5 — Historical backfill vs forward-only

**What we’re choosing:** **Forward-only** for v1: only settlements **after** this feature ships populate **`RelayerTransactions`**.

**Why not always backfill:** Old **`trans_id`** values live in **`UploadTransactionLog`** (and possibly ledger) but may include **mock** hashes, mixed formats, or high RPC volume to refetch receipts. Backfill is a **one-time script or ops run**, not required for runway math once new txs are recorded.

**Tradeoff:** Dashboards and 7d averages start **empty** until traffic accrues; **long-term** accuracy is fine. If you need history on day one, add a **separate** backfill job (filter real `0x` tx hashes, rate-limit RPC).

---

## 2. Codebase review vs spec (brief)

| Area | Today |
|------|--------|
| On-chain settlement | `_onchain_settle_payment` in `services/storage-upload/app.py` — Web3.py, synchronous receipt |
| Relayer key | `MNEMOSPARK_RELAYER_SECRET_ID` → Secrets Manager |
| Base RPC | `MNEMOSPARK_BASE_RPC_URL` on **PaymentSettleFunction** in `template.yaml` |
| DynamoDB | **UploadTransactionLogTable** has business fields + `trans_id`; no relayer analytics tables yet |
| Schedules | **StorageHousekeepingFunction** + EventBridge rule pattern in `template.yaml` |

---

## 3. Target architecture

- **Settlement path:** After successful receipt in `_onchain_settle_payment`, call a small shared helper (e.g. `services/common/relayer_ledger.py`) to **`PutItem`** **`RelayerTransactions`** (idempotent on tx hash).
- **Monitor:** New Lambda (e.g. `services/base-relayer-monitor`), EventBridge schedule, reads **`RelayerTransactions`**, writes **`RelayerStats`** + **`RelayerHealth`**, **`Publish`** to SNS on warning/critical.
- **Monitor IAM:** DynamoDB on the three new tables; `sns:Publish` on the alert topic; no private key.

---

## 4. Implementation phases

### Phase A — Infrastructure (`template.yaml`)

- Parameter **`RelayerWalletAddress`** → **`MNEMOSPARK_RELAYER_WALLET_ADDRESS`** on monitor Lambda.
- Tables: **RelayerTransactions**, **RelayerStats**, **RelayerHealth** (`${AWS::StackName}-…`).
- **RelayerAlertsTopic** + **email subscription** to **alerts@mnemospark.ai**.
- **BaseRelayerMonitorFunction** + role + EventBridge rule(s).
- Pass **`MNEMOSPARK_BASE_RPC_URL`** (or same ref as settlement) to the monitor.

### Phase B — Instrument `_onchain_settle_payment`

- Shared **`record_relayer_transaction(...)`** using receipt fields; **skip** in mock mode.
- Grant **PaymentSettle** (and any Lambda that can run onchain settlement) **PutItem** on **RelayerTransactionsTable** if not already covered by a shared role.

### Phase C — Monitor Lambda

- Query txs by wallet pk; compute periods; **get_balance**; runway; **Publish** SNS when degraded.

### Phase D — Tests & docs

- Unit tests for fee math, runway edge cases, idempotency.
- Operator note: confirm SNS email, where parameters live.

---

## 5. Success criteria

- **RelayerHealth** has balance + runway + status.
- **RelayerTransactions** populated for new on-chain settlements after deploy.
- **RelayerStats** has daily / weekly / monthly aggregates.
- SNS fires on **warning/critical**; **alerts@mnemospark.ai** confirmed in SNS.
- **ruff**, **pytest**, **`sam validate`** pass.

---

## 6. Follow-up (optional)

- Backfill script for historical **`trans_id`** (if product needs it).
- API or internal read path for health row (if ops wants console-free visibility).
- Code change to **disallow** on-chain settlement from **`/storage/upload`** if you want hard enforcement.

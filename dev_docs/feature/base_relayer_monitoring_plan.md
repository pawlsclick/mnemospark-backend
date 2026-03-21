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
| **Q4 — Relayer tx rows** | **Agreed: write-on-success-only.** **No** pending state, **no** pending reconciliation loop, **no** “reconcile every 5 minutes” requirement in v1. |
| **Q5 — History** | **Agreed: forward-only.** **No** automatic backfill from `UploadTransactionLog` in this feature. |
| **SNS encryption** | **Agreed: no topic encryption beyond SNS defaults** (no SSE-KMS on the topic). Monitor role needs only **`sns:Publish`** on the topic ARN — **no** extra KMS permissions. |

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

### 0.3 Ledger write when table env is missing (implementation rule)

- Add **`RELAYER_TRANSACTIONS_TABLE_NAME`** (name TBD but use this pattern) to **`PaymentSettleFunction`** in `template.yaml` with IAM **`dynamodb:PutItem`** on **`RelayerTransactionsTable`**.
- Inside **`record_relayer_transaction`**: if the env var is **unset or empty**, **skip** the Dynamo write, log a **single structured warning** (avoid log spam), and **do not** fail settlement. This protects any edge case where `_onchain_settle_payment` runs without the new env (e.g. local test, or upload path before template is fully aligned).

---

## 1. Rationale reference (Q4 & Q5) — already agreed

### Q4 — Why write-on-success-only

Settlement **already** waits for the receipt before returning. There is no separate broadcast phase to track in Dynamo for v1. Pending/reconcile is for **async** submit; skip it entirely per decision in **§0**.

### Q5 — Why forward-only

Avoids a one-time RPC crawl over historical `trans_id` values (mocks, rate limits). Backfill remains a **future optional** script if needed.

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

- **Settlement path:** After successful receipt in `_onchain_settle_payment`, call a small shared helper (e.g. `services/common/relayer_ledger.py`) to **`PutItem`** **`RelayerTransactions`** (idempotent on tx hash / sk).
- **Monitor:** New Lambda (e.g. `services/base-relayer-monitor`), EventBridge schedule, **`Query`** **`RelayerTransactions`** by wallet pk, compute aggregates → **`RelayerStats`** + **`RelayerHealth`**, **`sns:Publish`** on warning/critical.
- **Monitor IAM:** DynamoDB on the three new tables; `sns:Publish` on the alert topic; no private key.

---

## 4. Agent execution order (run in this sequence)

Execute **steps 1–4** in one coherent `template.yaml` (and related SAM) edit if preferred; the order below is the **dependency order** an agent must respect so nothing references missing resources.

| Step | What to do | Depends on |
|------|------------|------------|
| **1** | Define **DynamoDB** tables: `RelayerTransactions`, `RelayerStats`, `RelayerHealth` (`${AWS::StackName}-…`), keys per spec. | — |
| **2** | Add **parameter** `RelayerWalletAddress` (required for production; optional `Default: ""` only if you want `sam validate` / partial local flows without it—then monitor must no-op when empty). | — |
| **3** | Create **`AWS::SNS::Topic`** + standalone **`AWS::SNS::Subscription`** (`Protocol: email`, `Endpoint: alerts@mnemospark.ai`). Pass topic ARN to monitor via env. | — |
| **4** | Create **`BaseRelayerMonitorFunction`** + **dedicated IAM role**: DynamoDB read/write on the three tables; `sns:Publish` on topic; env: `MNEMOSPARK_RELAYER_WALLET_ADDRESS`, `MNEMOSPARK_BASE_RPC_URL`, table names, `RELAYER_ALERTS_TOPIC_ARN` (or equivalent). Add **EventBridge rule** → Lambda (e.g. `rate(30 minutes)` default; tune later). Add **Lambda permission** for EventBridge. | 1–3 |
| **5** | Extend **`PaymentSettleFunction`**: env `RELAYER_TRANSACTIONS_TABLE_NAME`; IAM **`PutItem`** on **RelayerTransactions** table ARN only. | 1 |
| **6** | Implement **`services/common/relayer_ledger.py`**: normalize address, build pk/sk, compute fee wei from receipt, **conditional PutItem** for idempotency. | 1 (schema) |
| **7** | Wire **`_onchain_settle_payment`** to call `record_relayer_transaction` after success; **mock** settlement mode → **no** ledger write. | 5, 6 |
| **8** | Implement **monitor handler** (`services/base-relayer-monitor/app.py`): load env, Web3 connect, **Query** txs for wallet, rollups, balance, runway, **UpdateItem**/Put **Health** + **Stats**, SNS on warn/critical. **No pending branch.** | 1, 3, 4, 6 (optional reuse of wei math) |
| **9** | **Unit tests**: ledger idempotency, fee math, runway edge cases (divide by zero), monitor logic with mocked boto3/Web3. | 6–8 |
| **10** | **ruff** + **pytest** + **`sam validate`**; fix any template lint noise per project norms. | 9 |
| **11** | **Deploy / ops (human):** set `RelayerWalletAddress`, deploy stack, **confirm SNS email** for `alerts@mnemospark.ai`, smoke-test one settlement + one monitor invocation. | 10 |

**Why this order:** Tables and topic ARNs must exist before Lambdas reference them. **PaymentSettle** must have IAM + env **before** settlement code performs writes. **Monitor** can be implemented after ledger helper exists; **tests last** before merge.

### 4.1 AWS IAM & CloudFormation checklist (AWS docs / MCP)

Cross-checked with **AWS documentation search** (CloudFormation + IAM). Implement exactly one **execution role per Lambda** (do not reuse PaymentSettle’s role for the monitor).

#### EventBridge schedule → monitor Lambda

Match the existing **`StorageHousekeepingScheduleRule`** + **`StorageHousekeepingInvokePermission`** pattern:

1. **`AWS::Events::Rule`** — `ScheduleExpression` (e.g. `rate(30 minutes)`), `State: ENABLED`, `Targets` entry with Lambda **Arn** and a stable **Id** (string unique per target).
2. **`AWS::Lambda::Permission`** — required so EventBridge can invoke the function:
   - `Action: lambda:InvokeFunction`
   - `Principal: events.amazonaws.com`
   - `FunctionName: !Ref BaseRelayerMonitorFunction` (or logical ID used)
   - `SourceArn: !GetAtt <RuleLogicalId>.Arn`

Reference: [AWS::Events::Rule](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-rule.html) (scheduled Lambda example + permission).

#### SNS topic + email subscription

1. **`AWS::SNS::Topic`** (alerts). **Do not** set SSE-KMS on the topic — **defaults only** per **§0** (no extra KMS IAM on the monitor role).
2. **`AWS::SNS::Subscription`** as a **standalone** resource (recommended for explicit control): `TopicArn`, `Protocol: email`, `Endpoint: alerts@mnemospark.ai`.  
   - CloudFormation creates the subscription; the address stays **pending** until the recipient **confirms** via AWS’s email.  
   Reference: [AWS::SNS::Subscription](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html).

3. Monitor Lambda env: e.g. **`RELAYER_ALERTS_TOPIC_ARN`** = topic ARN (or `!Ref` / `!GetAtt` as appropriate).

#### BaseRelayerMonitor Lambda execution role (new IAM role)

| Need | IAM |
|------|-----|
| CloudWatch Logs | Attach managed policy **`arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole`** (same pattern as other functions in this repo). |
| DynamoDB | **Identity-based** policy on the **three new table ARNs** only. Minimum actions for the described design: **`dynamodb:Query`**, **`GetItem`**, **`PutItem`**, **`UpdateItem`** on each of `RelayerTransactionsTable`, `RelayerStatsTable`, `RelayerHealthTable`. Add **`dynamodb:DescribeTable`** if the code calls describe (optional). **Do not** use `dynamodb:*` or `Resource: *`. |
| DynamoDB indexes (future) | If you add GSI/LSI later, extend **`Resource`** to include index ARNs (e.g. `!Sub '${TableArn}/index/*'`) per [DynamoDB IAM table + indexes](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/iam-policy-specific-table-indexes.html). v1 has **no** GSIs — table ARN only. |
| Publish alerts | **`sns:Publish`** on the **topic ARN** (`!Ref RelayerAlertsTopic` or equivalent). Same-account publish does **not** require a separate topic resource policy when the role is identity-based. |

**Not** granted on the monitor role: Secrets Manager, relayer private key, `PaymentSettle` resources.

#### PaymentSettleLambdaRole (extend existing role only)

Add one inline (or named) policy statement:

- **`dynamodb:PutItem`** (and only what idempotency needs — **`PutItem`** is sufficient for conditional put)  
- **`Resource`**: **`!GetAtt RelayerTransactionsTable.Arn`** only.

Do **not** add `Query`/`UpdateItem` on Stats/Health here unless a new API requires it.

#### Networking (Base RPC)

- If the monitor Lambda has **no VPC config** (like typical API Lambdas here), **HTTPS** to `MNEMOSPARK_BASE_RPC_URL` uses the default public path — no extra IAM.
- If you ever attach a **VPC**, you must provide **outbound internet** (e.g. NAT) or a **VPC interface endpoint** path compatible with your RPC provider; otherwise `eth_getBalance` / receipts will fail.

#### Log group (optional but consistent)

Add **`AWS::Logs::LogGroup`** for `/aws/lambda/<BaseRelayerMonitorFunction>` with **`RetentionInDays`** from **`ObservabilityLogRetentionDays`**, matching **`StorageHousekeepingFunction`** / **`PaymentSettleFunction`**.

---

## 5. Implementation phases (map to steps above)

- **Phase A (Infra):** Steps **1–5** + **4** (monitor function + schedule).
- **Phase B (Settlement write):** Steps **6–7**.
- **Phase C (Monitor):** Step **8**.
- **Phase D (Quality + ship):** Steps **9–11**.

---

## 6. Success criteria

- **RelayerHealth** has balance + runway + status.
- **RelayerTransactions** populated for new on-chain settlements after deploy (forward-only).
- **RelayerStats** has daily / weekly / monthly aggregates.
- SNS fires on **warning/critical**; **alerts@mnemospark.ai** subscription **confirmed** in AWS.
- **ruff**, **pytest**, **`sam validate`** pass.

---

## 7. Pending questions for the product owner

**None** — Q4/Q5 and **SNS encryption** (defaults only, no SSE-KMS) are locked in **§0**.

**Operational reminders (not blockers):**

- After first deploy, **confirm** the SNS email subscription.
- Ensure **`RelayerWalletAddress`** is set in every environment that runs the monitor.

**Optional later (explicitly out of scope for v1):**

- Backfill script for historical **`trans_id`**.
- Read API or admin view for **RelayerHealth**.
- Hard-disable on-chain on **`/storage/upload`**.

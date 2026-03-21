# Base relayer monitoring (operator note)

Scheduled observability for the **Base relayer wallet** used by **`POST /payment/settle`** (on-chain USDC settlement). This is **not** a public HTTP API; it runs as a **scheduled Lambda** plus **DynamoDB** and **SNS**.

Design reference: `dev_docs/feature/base_relayer_monitoring_spec.md` and `dev_docs/feature/base_relayer_monitoring_plan.md`.

## What gets deployed

| Resource | Purpose |
|----------|---------|
| **DynamoDB** `…-relayer-transactions` | One item per successful on-chain settlement (gas, fee, tx hash). Written from settlement code (best-effort). |
| **DynamoDB** `…-relayer-stats` | Rolling aggregates for **DAY** / **WEEK** / **MONTH** (current period only, recomputed each run). |
| **DynamoDB** `…-relayer-health` | Latest snapshot: balance, 7d averages, runway, **ok** / **warning** / **critical**. |
| **SNS topic** | Alerts when health is **warning** or **critical**. |
| **Email subscription** | `alerts@mnemospark.ai` — must be **confirmed** after first deploy. |
| **EventBridge rule** | Invokes the monitor Lambda on **`RelayerMonitorScheduleExpression`** (default `rate(30 minutes)`). |

Stack outputs include table names, topic ARN, monitor function ARN, and schedule rule ARN.

## Parameters (CloudFormation / SAM)

- **`RelayerWalletAddress`** — Relayer **public** address (must match the address derived from the relayer private key in Secrets Manager). Default is set in `template.yaml`; override per environment if needed. If set to **empty**, the monitor **exits successfully without work** (no RPC, no writes).
- **`BaseRpcUrl`** — Same Base RPC URL used for settlement; required for balance and (indirectly) for a healthy chain connection in the monitor.
- **`RelayerMonitorScheduleExpression`** — EventBridge schedule for the monitor (default `rate(30 minutes)`).

## After deploy

1. **SNS subscription** — In the AWS console (SNS → topic → subscriptions), confirm the **pending** email subscription for `alerts@mnemospark.ai`. Until confirmed, alert emails are not delivered.
2. **Smoke test** — After at least one successful on-chain settlement, check **RelayerTransactions** for a row under partition key `WALLET#<lowercase-0x-address>`. After the next schedule tick, check **RelayerHealth** for `sk` = `HEALTH#LATEST`.

## Reading state in DynamoDB

Convention (lowercase `0x` + 40 hex for the wallet in keys):

- **Transactions:** `pk` = `WALLET#0x…`, `sk` = `TX#<iso8601-utc>#0x<txhash>`.
- **Health:** `pk` = `WALLET#0x…`, `sk` = `HEALTH#LATEST`.
- **Stats:** `pk` = `WALLET#0x…#PERIOD#<DAY\|WEEK\|MONTH>#<period-value>` (e.g. `DAY#2025-03-21`, `WEEK#2025-W12`, `MONTH#2025-03`).

Useful item fields on **health**: `ethBalanceWei`, `avgFeePerTxWei_7d`, `avgTxPerDay_7d`, `estimatedDaysRemaining` (**`-1`** means “not computed”, e.g. no 7d spend), `status`, `updatedAt`.

Example (AWS CLI — replace table name and profile/region as needed):

```bash
aws dynamodb get-item \
  --table-name "<stack>-relayer-health" \
  --key '{"pk":{"S":"WALLET#0x604d308201626a0a8a67b46112943d08dbd99bc8"},"sk":{"S":"HEALTH#LATEST"}}'
```

## Logs and troubleshooting

- **CloudWatch log group:** `/aws/lambda/<BaseRelayerMonitorFunction>` (name includes stack logical ID from CloudFormation).
- **Monitor skips:** If wallet, RPC, or table env vars are missing, log line **`base_relayer_monitor_skip_missing_env`** and the invocation returns success.
- **Settlement without ledger rows:** Ledger writes are **best-effort**; Dynamo or config issues are logged as **`relayer_ledger_write_failed`** but do **not** fail on-chain settlement. Fix IAM/table env and watch the next settlement.

## Alerts

SNS publishes a JSON body including `status`, `wallet`, `ethBalanceWei`, `estimatedDaysRemaining`, and 7d averages when `status` is **warning** or **critical** (runway thresholds: under **3 days** = warning, under **1 day** = critical; see spec).

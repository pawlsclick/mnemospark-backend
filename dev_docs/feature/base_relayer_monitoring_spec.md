# Base Relayer Wallet Monitoring Spec

## Objective

Implement a scheduled monitoring subsystem for the **single** Base relayer wallet used in AWS Lambda payment settlement.

**Engineering principles**

- Prefer **minimal changes** to the existing codebase; **do not** introduce new stacks, languages, or client libraries unless necessary (this backend is **Python 3.13** + **Web3.py**, same as settlement today).
- **On-chain settlement is centralized** on **`POST /payment/settle`**; design monitoring and ledger writes around that flow.
- Use **polling only** (no WebSockets).

The subsystem must:

- Track daily, weekly, monthly transaction counts (aggregates)
- Track gas used and fee paid per relayer-submitted transaction
- Monitor ETH balance sufficiency for gas (runway)
- Persist data in DynamoDB (transactions + aggregates + latest health)
- Use relayer-submitted transactions recorded by the product as the source of truth for “what to account for”

---

## Required documentation (do not rediscover)

- Base: https://docs.base.org/get-started/base  
- Base RPC methods: https://docs.base.org/base-account/reference/core/provider-rpc-methods/standard-rpc-methods  
- Base fees: https://docs.base.org/base-chain/network-information/network-fees  
- Web3.py: https://web3py.readthedocs.io/  
- Receipt / effective gas price: use `eth_getTransactionReceipt` (via `web3.eth.get_transaction_receipt`)  
- Balance: `eth_getBalance` (via `web3.eth.get_balance`)

---

## Architecture

### Lambda A (existing — settlement)

- **`POST /payment/settle`** (and shared payment core) submits transactions and, after confirmation, **records each successful relayer tx** in **`RelayerTransactions`** (gas + fee from the receipt already held in process).

### Lambda B (new — monitor)

- Runs on **EventBridge** schedule(s).
- Recomputes **aggregates** and **health** (balance, 7d averages, runway).
- Publishes to **SNS** when health is **warning** or **critical** (email to **alerts@mnemospark.ai** per infra; see plan).

### Relayer address configuration

- Set **`MNEMOSPARK_RELAYER_WALLET_ADDRESS`** at deploy time (CloudFormation **parameter** → Lambda environment variable). The monitor Lambda uses this for DynamoDB partition keys and `eth_getBalance`; it does **not** need the private key.

---

## DynamoDB schema

### Table: RelayerTransactions

| Field | Type | Description |
|------|------|-------------|
| pk | string | WALLET#&lt;address&gt; |
| sk | string | TX#&lt;timestamp&gt;#&lt;txHash&gt; |
| txHash | string | Transaction hash |
| status | string | success \| reverted (v1 may be success-only; see plan) |
| gasUsed | string | From receipt |
| effectiveGasPriceWei | string | From receipt |
| feePaidWei | string | gasUsed × effectiveGasPrice (integer wei as string) |
| blockNumber | number | Confirmation block |
| submittedAt | string | ISO timestamp |
| confirmedAt | string | ISO timestamp |

### Table: RelayerStats

| Field | Type | Description |
|------|------|-------------|
| pk | string | WALLET#&lt;address&gt;#PERIOD#&lt;type&gt;#&lt;value&gt; |
| txCount | number | Total transactions |
| successCount | number | Successful txs |
| revertCount | number | Failed txs |
| totalGasUsed | string | Sum of gas |
| totalFeePaidWei | string | Total cost (wei string) |
| avgFeePaidWei | string | Average fee (wei string) |
| updatedAt | string | Timestamp |

### Table: RelayerHealth

| Field | Type | Description |
|------|------|-------------|
| pk | string | WALLET#&lt;address&gt; |
| sk | string | HEALTH#LATEST |
| ethBalanceWei | string | Wallet balance |
| avgFeePerTxWei_7d | string | Rolling average |
| avgTxPerDay_7d | number | Rolling volume |
| estimatedDaysRemaining | number | Runway (nullable / sentinel if undefined) |
| status | string | ok \| warning \| critical |

---

## Gas calculation

```
feePaidWei = gasUsed * effectiveGasPrice
```

Source: transaction receipt from RPC (same fields Web3.py exposes on the receipt object).

---

## Balance monitoring logic

```
estimatedDailyGasSpend = avgTxPerDay_7d * avgFeePerTxWei_7d
estimatedDaysRemaining = balanceWei / estimatedDailyGasSpend
```

Handle division by zero (no txs or zero fee) with an explicit **unknown / safe default** in implementation.

### Thresholds

| Status | Condition |
|--------|-----------|
| OK | ≥ 3 days runway |
| WARNING | &lt; 3 days |
| CRITICAL | &lt; 1 day |

---

## Lambda monitor flow

1. Load **`MNEMOSPARK_RELAYER_WALLET_ADDRESS`** and Base RPC URL from environment.
2. Load transactions for the wallet from **`RelayerTransactions`** (**query** by pk). v1 is **write-on-success-only** — **no** pending reconciliation step.
3. Compute daily / weekly / monthly aggregates → **`RelayerStats`**.
4. **`eth_getBalance`** for relayer address.
5. Compute runway → **`RelayerHealth`**.
6. If status is warning or critical, **publish message to SNS topic** (email subscription to **alerts@mnemospark.ai**).

---

## Scheduling (EventBridge)

Suggested defaults (tunable per environment):

- **Single rule:** stats + health + balance in one invocation (e.g. `rate(30 minutes)`).

---

## Production requirements

- Dedicated Base RPC provider (not an unauthenticated public endpoint in production).
- RPC URL supplied the same way as today for settlement (parameter / secrets pattern already used for **`MNEMOSPARK_BASE_RPC_URL`**).
- RPC retries and timeouts.
- Idempotent DynamoDB writes.

---

## Alerts (SNS email)

- **Yes:** Amazon SNS can deliver to **email** by creating a topic subscription with **Protocol `email`** and **Endpoint `alerts@mnemospark.ai`**.
- The recipient must **confirm** the subscription once via the link AWS sends (standard SNS behavior).

---

## Future extensions (not required now)

- ERC-20 transfer tracking via logs  
- Full chain indexing  
- Real-time dashboards via WebSockets  
- Multi-wallet support  

---

## Summary

This system uses **Web3.py** (existing stack) for Base RPC, **DynamoDB** for analytics state, **Lambda** for settlement-side writes and scheduled monitoring, and **SNS** for email alerts—without introducing parallel TypeScript/viem clients or unnecessary new patterns.

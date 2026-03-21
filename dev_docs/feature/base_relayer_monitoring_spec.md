# Base Relayer Wallet Monitoring Spec

## Objective

Implement a scheduled monitoring subsystem for a Base relayer wallet used in AWS Lambda transaction settlement.

The subsystem must:
- Track daily, weekly, monthly transaction counts
- Track gas used and fee paid per transaction
- Monitor ETH balance sufficiency for gas
- Persist data in DynamoDB (transactions + aggregates)
- Use polling only (no WebSockets)
- Use relayer-submitted transactions as primary source of truth

---

## Required Documentation (DO NOT REDISCOVER)

- Base Docs: https://docs.base.org/get-started/base
- Base RPC Methods: https://docs.base.org/base-account/reference/core/provider-rpc-methods/standard-rpc-methods
- Base Fees: https://docs.base.org/base-chain/network-information/network-fees
- viem Docs: https://viem.sh
- viem getTransactionReceipt: https://viem.sh/docs/actions/public/getTransactionReceipt
- viem getBalance: https://viem.sh/docs/actions/public/getBalance

---

## Architecture

### Components

**Lambda A (existing – settlement)**
- Submits transactions
- Writes transaction metadata to DynamoDB

**Lambda B (new – monitor)**
- Runs on schedule (EventBridge)
- Fetches transaction receipts
- Computes gas + aggregates
- Monitors wallet balance
- Writes stats to DynamoDB

---

## DynamoDB Schema

### Table: RelayerTransactions

| Field | Type | Description |
|------|------|------------|
| pk | string | WALLET#<address> |
| sk | string | TX#<timestamp>#<txHash> |
| txHash | string | Transaction hash |
| status | string | pending \| success \| reverted |
| gasUsed | string | From receipt |
| effectiveGasPriceWei | string | From receipt |
| feePaidWei | string | gasUsed * effectiveGasPrice |
| blockNumber | number | Confirmation block |
| submittedAt | string | ISO timestamp |
| confirmedAt | string | ISO timestamp |

---

### Table: RelayerStats

| Field | Type | Description |
|------|------|------------|
| pk | string | WALLET#<address>#PERIOD#<type>#<value> |
| txCount | number | Total transactions |
| successCount | number | Successful txs |
| revertCount | number | Failed txs |
| totalGasUsed | string | Sum of gas |
| totalFeePaidWei | string | Total cost |
| avgFeePaidWei | string | Average fee |
| updatedAt | string | Timestamp |

---

### Table: RelayerHealth

| Field | Type | Description |
|------|------|------------|
| pk | string | WALLET#<address> |
| sk | string | HEALTH#LATEST |
| ethBalanceWei | string | Wallet balance |
| avgFeePerTxWei_7d | string | Rolling average |
| avgTxPerDay_7d | number | Rolling volume |
| estimatedDaysRemaining | number | Runway |
| status | string | ok \| warning \| critical |

---

## Gas Calculation

```
feePaidWei = gasUsed * effectiveGasPrice
```

Source: transaction receipt via `getTransactionReceipt`

---

## Balance Monitoring Logic

```
estimatedDailyGasSpend = avgTxPerDay_7d * avgFeePerTxWei_7d
estimatedDaysRemaining = balanceWei / estimatedDailyGasSpend
```

### Thresholds

| Status | Condition |
|--------|----------|
| OK | >= 3 days runway |
| WARNING | < 3 days |
| CRITICAL | < 1 day |

---

## Lambda Monitor Flow

1. Load relayer wallet address
2. Query DynamoDB for pending transactions
3. Fetch receipts using viem
4. Update transaction records
5. Compute daily / weekly / monthly aggregates
6. Fetch wallet balance via RPC
7. Compute gas runway
8. Persist stats + health
9. Emit alert if needed

---

## Implementation Notes

### viem client setup

```ts
import { createPublicClient, http } from 'viem'
import { base } from 'viem/chains'

export const client = createPublicClient({
  chain: base,
  transport: http(process.env.BASE_RPC_URL!)
})
```

---

### Fetch receipt

```ts
const receipt = await client.getTransactionReceipt({ hash })
```

---

### Fetch balance

```ts
const balance = await client.getBalance({ address })
```

---

## Scheduling

Use AWS EventBridge:

- Every 5 minutes → reconcile pending transactions
- Every 15–60 minutes → recompute stats + health
- Daily → finalize aggregates

---

## Production Requirements

- Use a dedicated Base RPC provider (not public endpoint)
- Store RPC URL in AWS Secrets Manager or SSM
- Handle RPC retries and timeouts
- Ensure idempotent updates to DynamoDB

---

## Future Extensions (NOT REQUIRED NOW)

- ERC20 transfer tracking via logs
- Full chain indexing
- Real-time dashboards via WebSockets
- Multi-wallet support

---

## Summary

This system uses:

- viem for Base RPC interaction
- DynamoDB for state + analytics
- Lambda for scheduled monitoring

It avoids unnecessary complexity while providing full visibility into relayer performance, cost, and operational health.

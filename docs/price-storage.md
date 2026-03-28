# POST /price-storage

Create a storage price quote for a wallet-scoped object. The backend calculates S3 storage and outbound data transfer costs from the AWS Price List, applies a configurable markup, persists the quote in DynamoDB with TTL, and returns the quote for use in upload and payment flows.

## Configuration (Lambda environment)

The price-storage Lambda reads:

| Variable | Meaning | Default when unset |
|----------|---------|---------------------|
| `PRICE_STORAGE_FLOOR` | Minimum USD for the AWS **subtotal** (storage + transfer) **before** markup. | `0` (no floor; quotes scale with estimated usage). |
| `PRICE_STORAGE_MARKUP` | Markup as a percentage of that subtotal (e.g. `10` means 10%). | `0` |

Formula:

`storage_price = round(max(aws_subtotal, PRICE_STORAGE_FLOOR) * (1 + PRICE_STORAGE_MARKUP / 100), 2)` where `aws_subtotal = storage_cost + transfer_cost` from the AWS Price List API.

In SAM, these are supplied as stack parameters **`PriceStorageFloor`** and **`PriceStorageMarkup`** (defaults `0`) and passed through to the Lambda environment.

**GitHub Actions:** Adding `PRICE_STORAGE_FLOOR` or `PRICE_STORAGE_MARKUP` only under the repository or environment **Variables** UI does **not** update the Lambda until the next deploy passes them into CloudFormation. The staging and production workflows map **`vars.PRICE_STORAGE_FLOOR`** and **`vars.PRICE_STORAGE_MARKUP`** to those parameters (defaulting to `0` when unset). After changing values, run a deploy (push to `main` for staging, or **Promote to Production** for prod).

For manual or emergency deploys, pass them explicitly, for example: `PriceStorageFloor=2 PriceStorageMarkup=30`.

## Authentication

**Wallet proof** (recommended). Send the `X-Wallet-Signature` header with a valid EIP-712 signature over the request (method, path, wallet address, nonce, timestamp). If present, the backend verifies it and can use it for per-wallet rate limiting. Some deployments may allow unauthenticated price requests.

## Request

**Content-Type:** `application/json`

| Field           | Type   | Required | Description |
|----------------|--------|----------|-------------|
| `wallet_address` | string | Yes      | EVM wallet address (0x-prefixed, 20-byte hex). |
| `object_id`      | string | Yes      | Object identifier from a prior backup step. |
| `object_id_hash` | string | Yes      | SHA-256 hash of the backup archive. |
| `gb`             | number | Yes      | Storage size in GB (must be > 0). |
| `provider`       | string | Yes      | Storage provider; only `aws` is supported. |
| `region`         | string | Yes      | AWS region (e.g. `us-east-1`). |

Example:

```json
{
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "object_id": "backup-2024-01-15",
  "object_id_hash": "a1b2c3...",
  "gb": 0.000403116,
  "provider": "aws",
  "region": "us-east-1"
}
```

## Responses

### 200 OK

Quote created. Use `quote_id` for `/payment/settle` and `/storage/upload`.

```json
{
  "timestamp": "2024-01-15 10:30:00",
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "storage_price": 0.42,
  "addr": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "object_id": "backup-2024-01-15",
  "object_id_hash": "a1b2c3...",
  "object_size_gb": 0.000403116,
  "provider": "aws",
  "location": "us-east-1"
}
```

### 400 Bad Request

Request validation failed (missing/invalid fields, invalid provider, or `gb` not greater than 0).

```json
{
  "error": "Bad request",
  "message": "gb must be greater than 0"
}
```

### 403 Forbidden

Wallet proof invalid or rejected (when required).

```json
{
  "error": "forbidden",
  "message": "wallet_proof_invalid"
}
```

### 500 Internal Server Error

Unhandled error (e.g. DynamoDB or Pricing API failure).

```json
{
  "error": "Internal error",
  "message": "Failed to process price-storage request"
}
```

## Notes

- Quotes have a TTL (e.g. 1 hour). After expiry, the quote is not found for payment or upload.
- Next steps: call `POST /payment/settle` with the returned `quote_id`, then `POST /storage/upload` with the same quote and payment proof.

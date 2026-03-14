# POST /price-storage

Create a storage price quote for a wallet-scoped object. The backend calculates S3 storage and outbound data transfer costs from the AWS Price List, applies a configurable markup, persists the quote in DynamoDB with TTL, and returns the quote for use in upload and payment flows.

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

# POST /storage/upload

Upload encrypted object data to the wallet-scoped S3 bucket. The backend requires a valid quote and an existing confirmed payment ledger record for the quote. Supports **inline** mode (ciphertext in the JSON body) or **presigned** mode (returns a presigned S3 PUT URL; client uploads then calls `POST /storage/upload/confirm`).

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature`. The authorizer wallet must match `wallet_address` in the body.

## Request

**Content-Type:** `application/json`

**Headers:**

| Header            | Required | Description |
|-------------------|----------|-------------|
| `Idempotency-Key` | Yes for presigned | Idempotency key for deduplication; required when `mode` is `presigned`. |
| `PAYMENT-SIGNATURE` / `x-payment` | No | Payment authorization (if 402 was returned previously). |

| Field                 | Type   | Required | Description |
|-----------------------|--------|----------|-------------|
| `quote_id`            | string | Yes      | Quote ID from price-storage, after payment settle. |
| `wallet_address`      | string | Yes      | EVM wallet address (must match authorizer). |
| `object_id`           | string | Yes      | Object identifier (must match quote). |
| `object_id_hash`      | string | Yes      | SHA-256 of backup archive (must match quote). |
| `wrapped_dek`         | string | Yes      | Base64-encoded wrapped data encryption key. |
| `object_key`          | string | No       | Override for object key (defaults to `object_id`); single path segment. |
| `mode`                | string | No       | `inline` (default) or `presigned`. |
| `ciphertext`          | string | Yes if inline | Base64-encoded encrypted content for `inline` mode. |
| `content_sha256`      | string | No       | SHA-256 hash of ciphertext. |
| `content_length_bytes`| integer| No       | Content length (e.g. for presigned). |
| `provider` / `location` | string | No    | Override provider/region. |

Example (inline):

```json
{
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "object_id": "backup-2024-01-15",
  "object_id_hash": "a1b2c3...",
  "wrapped_dek": "base64...",
  "mode": "inline",
  "ciphertext": "base64EncodedCiphertext..."
}
```

Example (presigned): same fields but `mode: "presigned"`, no `ciphertext`; include `Idempotency-Key` header and optionally `content_length_bytes`.

## Responses

### 200 OK

Upload accepted or completed. For presigned mode, use `upload_url` and `upload_headers` to PUT the ciphertext, then call `POST /storage/upload/confirm`.

**Inline completed:**

```json
{
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "addr": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "trans_id": "...",
  "storage_price": 0.42,
  "object_id": "backup-2024-01-15",
  "object_key": "backup-2024-01-15",
  "provider": "aws",
  "bucket_name": "mnemospark-abc123def456",
  "location": "us-east-1"
}
```

**Presigned (confirmation required):**

```json
{
  "upload_url": "https://s3.us-east-1.amazonaws.com/...",
  "upload_headers": { "x-amz-meta-wrapped-dek": "..." },
  "confirmation_required": true,
  "object_key": "backup-2024-01-15",
  "bucket_name": "mnemospark-abc123def456",
  "location": "us-east-1"
}
```

### 207 Multi-Status

Payment settled but upload failed (e.g. S3 transient error). Client may retry upload with same idempotency key.

### 400 Bad Request

Validation failure (e.g. missing required field, `object_id_hash` / `object_id` / `wallet_address` mismatch with quote, invalid `object_key`).

### 402 Payment Required

No payment ledger record for this quote; call `POST /payment/settle` first. Response may include `PAYMENT-REQUIRED` headers with payment details.

### 403 Forbidden

Wallet proof invalid or wallet does not match body.

### 404 Not Found

Quote not found or expired.

### 409 Conflict

Idempotency conflict or state conflict (e.g. duplicate upload for same idempotency key).

### 500 Internal Server Error

Unhandled error.

## Notes

- **Payment required:** Upload succeeds only if a payment ledger record exists for `(wallet_address, quote_id)`; settle payment first.
- **Idempotency:** For presigned mode, send `Idempotency-Key` header. Retries with the same key are deduplicated.
- **Presigned flow:** After PUT to `upload_url`, call `POST /storage/upload/confirm` with `quote_id`, `wallet_address`, `object_key`, and `idempotency_key`.

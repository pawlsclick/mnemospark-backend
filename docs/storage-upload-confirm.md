# POST /storage/upload/confirm

Confirm that a presigned upload has been completed. After the client uploads ciphertext to the presigned S3 URL from `POST /storage/upload` (presigned mode), it calls this endpoint to finalize the transaction state (e.g. upload transaction log, idempotency record).

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature`. The authorizer wallet must match `wallet_address` in the body.

## Request

**Content-Type:** `application/json`

| Field             | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `quote_id`       | string | Yes      | Quote ID used for the upload. |
| `wallet_address` | string | Yes      | EVM wallet address (must match authorizer). |
| `object_key`     | string | Yes      | Object key used in the presigned upload (single path segment). |
| `idempotency_key`| string | Yes      | Same `Idempotency-Key` value sent with the upload request. |

Example:

```json
{
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "object_key": "backup-2024-01-15",
  "idempotency_key": "presigned-upload-abc123"
}
```

## Responses

### 200 OK

Upload confirmation finalized. Response body may match the shape of a completed upload (e.g. `object_key`, `bucket_name`, `location`).

```json
{
  "object_key": "backup-2024-01-15",
  "bucket_name": "mnemospark-abc123def456",
  "location": "us-east-1"
}
```

### 400 Bad Request

Validation failure (e.g. missing field, invalid `object_key`).

```json
{
  "error": "Bad request",
  "message": "object_key must be a single path segment"
}
```

### 403 Forbidden

Wallet proof invalid or wallet does not match body.

### 404 Not Found

Quote, bucket, or object not found (e.g. presigned upload not yet completed or key mismatch).

### 409 Conflict

Idempotency or state conflict (e.g. confirmation already recorded for this idempotency key).

### 500 Internal Server Error

Unhandled error.

## Notes

- Call this only after successfully PUTting the ciphertext to the presigned URL from `POST /storage/upload` (presigned mode).
- Use the same `idempotency_key` as in the upload request for correct deduplication.

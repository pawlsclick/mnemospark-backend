# GET /storage/ls and POST /storage/ls

Return metadata for a single object in the wallet-scoped bucket: key, size, and bucket name. Use GET with query parameters or POST with a JSON body.

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature`. The authorizer wallet must match the wallet used for the request.

## Request

### GET /storage/ls

**Query parameters:**

| Parameter        | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `wallet_address`| string | Yes      | EVM wallet address (0x-prefixed). |
| `object_key`    | string | Yes      | Object key (single path segment). |
| `location`      | string | No       | AWS region override (e.g. `us-east-1`). |

### POST /storage/ls

**Content-Type:** `application/json`

| Field             | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `wallet_address` | string | Yes      | EVM wallet address. |
| `object_key`     | string | Yes      | Object key (single path segment). |
| `location`       | string | No       | AWS region override. |

Example (POST body):

```json
{
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "object_key": "backup-2024-01-15"
}
```

## Responses

### 200 OK

Object metadata.

```json
{
  "success": true,
  "key": "backup-2024-01-15",
  "size_bytes": 1048576,
  "bucket": "mnemospark-abc123def456"
}
```

### 400 Bad Request

Validation failure (e.g. missing `wallet_address` or `object_key`, invalid address, or `object_key` containing `/` or `..`).

```json
{
  "error": "Bad request",
  "message": "object_key must be a single path segment"
}
```

### 403 Forbidden

Wallet proof invalid or wallet does not match request.

### 404 Not Found

Bucket or object not found (e.g. wallet has no bucket yet or object key does not exist).

```json
{
  "error": "not_found",
  "message": "Object not found: backup-2024-01-15"
}
```

### 500 Internal Server Error

Unhandled error.

## Notes

- For wallets that have never uploaded, the bucket may not exist; the backend returns 400 "Bucket not found" in that case (documented as 404-style semantics in the API).
- Only one object key per request; this is not a list-all operation.

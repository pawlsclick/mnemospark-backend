# DELETE /storage/delete and POST /storage/delete

Delete an object from the wallet-scoped S3 bucket. If the bucket becomes empty after the delete, the bucket is also deleted. Use DELETE with query parameters or POST with a JSON body.

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature`. The authorizer wallet must match the wallet in the request.

## Request

### DELETE /storage/delete

**Query parameters:**

| Parameter        | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `wallet_address`| string | Yes      | EVM wallet address (0x-prefixed). |
| `object_key`    | string | Yes      | Object key (single path segment). |
| `location`      | string | No       | AWS region override. |

### POST /storage/delete

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

Object deleted. If the bucket was empty after the delete, it was also removed (`bucket_deleted: true`).

```json
{
  "success": true,
  "key": "backup-2024-01-15",
  "bucket": "mnemospark-abc123def456",
  "bucket_deleted": false
}
```

### 400 Bad Request

Validation failure (e.g. missing `wallet_address` or `object_key`, invalid address, or invalid `object_key`).

```json
{
  "error": "Bad request",
  "message": "object_key must be a single path segment"
}
```

### 403 Forbidden

Wallet proof invalid or wallet does not match request.

### 404 Not Found

Bucket or object not found (nothing to delete).

```json
{
  "error": "object_not_found",
  "message": "Object not found"
}
```

### 500 Internal Server Error

Unhandled error.

## Notes

- Deletion is permanent. The object and, if empty, the bucket are removed.
- Only one object key per request.

# GET /storage/ls and POST /storage/ls

Wallet-scoped storage introspection: **stat** one object (`object_key` set) or **list** all keys in the bucket (`object_key` omitted). Use GET with query parameters or POST with a JSON body.

**OpenAPI:** `0.1.1` adds list mode; stat responses are unchanged from earlier versions.

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature`. The authorizer wallet must match the wallet used for the request.

## Stat mode (`object_key` present)

Same as the original single-object metadata flow: S3 `HeadObject` on the key.

### GET — query parameters

| Parameter         | Type   | Required | Description |
|-------------------|--------|----------|-------------|
| `wallet_address`  | string | Yes      | EVM wallet address (0x-prefixed). |
| `object_key`      | string | Yes      | Object key (single path segment). |
| `location`        | string | No       | AWS region override (e.g. `us-east-1`). |

### POST — JSON body

| Field             | Type   | Required | Description |
|-------------------|--------|----------|-------------|
| `wallet_address`  | string | Yes      | EVM wallet address. |
| `object_key`      | string | Yes      | Object key (single path segment). |
| `location`        | string | No       | AWS region override. |

### 200 OK (stat)

```json
{
  "success": true,
  "key": "backup-2024-01-15",
  "size_bytes": 1048576,
  "bucket": "mnemospark-abc123def456"
}
```

### 404 Not Found (stat)

Bucket missing or object key not found.

```json
{
  "error": "object_not_found",
  "message": "Object not found: backup-2024-01-15"
}
```

## List mode (`object_key` omitted)

S3 `ListObjectsV2` on the wallet bucket. **Empty bucket:** `200` with `"objects": []` (not 404).

### GET — query parameters

| Parameter              | Type    | Required | Description |
|------------------------|---------|----------|-------------|
| `wallet_address`       | string  | Yes      | EVM wallet address. |
| `object_key`           | string  | No       | Omit for list mode. |
| `location`             | string  | No       | AWS region override. |
| `continuation_token`   | string  | No       | Pagination token from prior response. |
| `max_keys`             | integer | No       | Page size, **1–1000** (default **1000**). |
| `prefix`               | string  | No       | Optional S3 key prefix filter. |

### POST — JSON body

| Field                  | Type    | Required | Description |
|------------------------|---------|----------|-------------|
| `wallet_address`       | string  | Yes      | EVM wallet address. |
| `object_key`           | string  | No       | Omit for list mode. |
| `location`             | string  | No       | AWS region override. |
| `continuation_token`   | string  | No       | Pagination token. |
| `max_keys`             | integer | No       | 1–1000, default 1000. |
| `prefix`               | string  | No       | Optional prefix filter. |

Example list request (POST):

```json
{
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "max_keys": 100
}
```

### 200 OK (list)

```json
{
  "success": true,
  "list_mode": true,
  "bucket": "mnemospark-abc123def456",
  "objects": [
    {
      "key": "backup-2024-01-15",
      "size_bytes": 1048576,
      "last_modified": "2024-01-15T12:00:00Z"
    }
  ],
  "is_truncated": false,
  "next_continuation_token": null
}
```

When `is_truncated` is `true`, repeat the request with `continuation_token` set to `next_continuation_token`.

## Common errors

### 400 Bad Request

Validation failure (e.g. missing `wallet_address`, invalid address, invalid `max_keys`, or `object_key` containing `/` or `..` in stat mode).

```json
{
  "error": "Bad request",
  "message": "object_key must be a single path segment"
}
```

### 403 Forbidden

Wallet proof invalid or wallet does not match request.

### 404 Not Found

**List mode:** bucket does not exist for this wallet (same as stat bucket missing).

**Stat mode:** bucket or object not found.

### 500 Internal Server Error

Unhandled error.

## Notes

- For wallets that have never uploaded, the bucket may not exist; the backend returns **404** `bucket_not_found`.
- List mode requires **`s3:ListBucket`** on the wallet bucket (configured on the StorageLs Lambda role).
- Friendly display names and human-readable sizes are **client-side** (not returned by this API).

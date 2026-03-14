# GET /storage/download and POST /storage/download

Generate a short-lived presigned S3 GET URL for downloading an object from the wallet-scoped bucket. Use GET with query parameters or POST with a JSON body. Only GET and POST are supported; other methods return 405.

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature`. The authorizer wallet must match the wallet in the request.

## Request

### GET /storage/download

**Query parameters:**

| Parameter            | Type    | Required | Description |
|----------------------|---------|----------|-------------|
| `wallet_address`     | string  | Yes      | EVM wallet address (0x-prefixed). |
| `object_key`         | string  | Yes      | Object key (single path segment). |
| `location`           | string  | No       | AWS region override. |
| `expires_in_seconds` | integer | No       | Presigned URL TTL in seconds (1–3600); default typically 300. |

### POST /storage/download

**Content-Type:** `application/json`

| Field                 | Type    | Required | Description |
|-----------------------|---------|----------|-------------|
| `wallet_address`      | string  | Yes      | EVM wallet address. |
| `object_key`          | string  | Yes      | Object key (single path segment). |
| `location`            | string  | No       | AWS region override. |
| `expires_in_seconds`  | integer | No       | Presigned URL TTL (1–3600). |

Example (POST body):

```json
{
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "object_key": "backup-2024-01-15",
  "expires_in_seconds": 600
}
```

## Responses

### 200 OK

Presigned download URL and metadata.

```json
{
  "download_url": "https://s3.us-east-1.amazonaws.com/mnemospark-abc123/backup-2024-01-15?X-Amz-...",
  "object_key": "backup-2024-01-15",
  "expires_in_seconds": 600
}
```

The client uses `download_url` with a simple GET (no auth) to retrieve the object bytes. The URL expires after `expires_in_seconds`.

### 400 Bad Request

Validation failure (e.g. missing required field, invalid `object_key`, or `expires_in_seconds` out of range).

### 403 Forbidden

Wallet proof invalid or wallet does not match request.

### 404 Not Found

Bucket or object not found.

```json
{
  "error": "object_not_found",
  "message": "Object not found: backup-2024-01-15",
  "details": "..."
}
```

### 405 Method Not Allowed

Only GET and POST are supported.

### 500 Internal Server Error

Unhandled error.

## Notes

- The response does not include the object content; it returns a URL. Follow the URL with a GET to download the ciphertext (decrypt client-side).
- Presigned URLs are valid only for the specified TTL and for the single object.

# POST /payment/settle

Verify and settle payment for storage. The backend verifies EIP-712 TransferWithAuthorization (or equivalent) from headers or body, settles in mock or on-chain mode, and persists a durable payment ledger record. There are two request shapes: **quote settlement** (after `POST /price-storage`) and **monthly renewal** (no new quote row).

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature` with a valid EIP-712 signature. The authorizer context must match the request body `wallet_address`.

## Request

**Content-Type:** `application/json`

**Headers (optional for payment):**

| Header             | Description |
|--------------------|-------------|
| `PAYMENT-SIGNATURE` | Base64-encoded payment authorization envelope (preferred). |
| `x-payment`         | Alternate payment authorization header. |

### Mode 1: Quote settlement

| Field             | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `quote_id`       | string | Yes      | Quote ID from `POST /price-storage`. |
| `wallet_address` | string | Yes      | EVM wallet address (must match authorizer). |
| `payment`        | object | No       | Inline payment authorization payload. |
| `payment_authorization` | object or string | No | Alternate inline payment envelope. |

Do not send `renewal` or use it as `false` in this mode.

Example:

```json
{
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
}
```

### Mode 2: Monthly renewal

No `quote_id` and no `QUOTES_TABLE` read. The server loads **active storage inventory** for `(wallet_address, object_key)`, uses `storage_price` as the expected amount, and `HeadObject` in the stored S3 region.

| Field             | Type    | Required | Description |
|------------------|---------|----------|-------------|
| `wallet_address` | string  | Yes      | EVM wallet address (must match authorizer). |
| `renewal`        | boolean | Yes      | Must be `true`. |
| `object_key`     | string  | Yes      | Object key for the stored file. |
| `payment`        | object  | No       | Inline payment authorization payload. |
| `payment_authorization` | object or string | No | Alternate inline payment envelope. |

**Synthetic ledger `quote_id`:** `renewal#YYYY-MM#<url_safe_object_key>` where `YYYY-MM` is the UTC billing month at settle time and `<url_safe_object_key>` is a deterministic encoding of `object_key` (same as the renewal log sort key suffix). This id is used for the payment ledger and idempotency, not for the quotes table.

Example:

```json
{
  "renewal": true,
  "object_key": "550e8400-e29b-41d4-a716-446655440000/1700000000.enc",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
}
```

Payment can be sent via `PAYMENT-SIGNATURE` or `x-payment` header (base64 JSON) or in the body for both modes.

## Responses

### 200 OK

Payment settled and persisted. For quote mode, the client can call `POST /storage/upload` with the same `quote_id`.

```json
{
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "trans_id": "0xabc...",
  "network": "eip155:8453",
  "asset": "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
  "amount": "420000",
  "payment_status": "confirmed",
  "timestamp": "2024-01-15 10:35:00"
}
```

Optional fields (when applicable):

- `result`: `"already_settled"` — idempotent retry (ledger or renewal log already recorded).
- `renewal`, `object_key`, `billing_period` — renewal mode metadata.

### 400 Bad Request

Invalid request body or payment payload.

```json
{
  "error": "Bad request",
  "message": "payment signature is required"
}
```

### 402 Payment Required

Payment authorization missing, invalid, or insufficient. Response may include `PAYMENT-REQUIRED` / `x-payment-required` headers with payment requirements.

```json
{
  "error": "payment_required",
  "message": "Payment authorization is invalid",
  "details": {}
}
```

### 403 Forbidden

Wallet proof missing or wallet does not match request.

```json
{
  "error": "forbidden",
  "message": "wallet_address does not match authorized wallet"
}
```

### 404 Not Found

**Quote mode:** quote not found or expired.

```json
{
  "error": "quote_not_found",
  "message": "Quote not found or expired"
}
```

**Renewal mode:**

- `renewal_not_registered` — no active inventory row for this wallet/object.
- `object_not_in_storage` — inventory exists but object is missing in S3.

### 409 Conflict

Duplicate settlement for the same ledger key (quote or synthetic renewal id) or renewal log row for the same month.

```json
{
  "error": "conflict",
  "message": "Payment already settled for this quote"
}
```

### 500 Internal Server Error

Unhandled error.

```json
{
  "error": "Internal error",
  "message": "..."
}
```

## Notes

- **Quote mode:** settlement is required before `POST /storage/upload`; the upload Lambda checks for a payment ledger record for `(wallet_address, quote_id)`.
- **Renewal mode:** proof for the UTC month is stored in `RENEWAL_TRANSACTION_LOG`. Storage housekeeping in `renewal_calendar` mode checks renewal by calendar (see deployment `HOUSEKEEPING_MODE` and schedule).
- Duplicate settlements are rejected with **409** or may return **200** with `result: already_settled`, mirroring idempotent client retries.

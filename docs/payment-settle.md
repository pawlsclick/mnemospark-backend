# POST /payment/settle

Verify and settle payment for a storage quote. The backend loads the quote, verifies EIP-712 TransferWithAuthorization (or equivalent) payment authorization from headers or body, settles in mock or on-chain mode, and writes a durable payment ledger record. Upload requires a successful settlement for the same `quote_id` and wallet before proceeding.

## Authentication

**Wallet proof** (required). Send `X-Wallet-Signature` with a valid EIP-712 signature. The authorizer context must match the request body `wallet_address`.

## Request

**Content-Type:** `application/json`

**Headers (optional for payment):**

| Header             | Description |
|--------------------|-------------|
| `PAYMENT-SIGNATURE` | Base64-encoded payment authorization envelope (preferred). |
| `x-payment`         | Alternate payment authorization header. |

| Field             | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `quote_id`       | string | Yes      | Quote ID from `POST /price-storage`. |
| `wallet_address` | string | Yes      | EVM wallet address (must match authorizer). |
| `payment`        | object | No       | Inline payment authorization payload. |
| `payment_authorization` | object or string | No | Alternate inline payment envelope. |

Example:

```json
{
  "quote_id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
}
```

Payment can be sent via `PAYMENT-SIGNATURE` or `x-payment` header (base64 JSON) or in the body.

## Responses

### 200 OK

Payment settled and persisted. The client can now call `POST /storage/upload` with this `quote_id`.

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

Quote not found or expired.

```json
{
  "error": "quote_not_found",
  "message": "Quote not found or expired"
}
```

### 409 Conflict

Duplicate settlement attempted for the same quote (idempotency / ledger conflict).

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

- Settlement is required before `POST /storage/upload`; the upload Lambda checks for an existing payment ledger record for `(wallet_address, quote_id)`.
- Duplicate settlements for the same quote are rejected with 409.

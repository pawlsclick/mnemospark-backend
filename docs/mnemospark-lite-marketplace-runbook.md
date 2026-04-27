# Mnemospark Lite marketplace: first settlement + verification runbook

This runbook is for verifying that the mnemospark-lite marketplace storage facade is:

- accepting x402 payments via CDP facilitator
- creating upload slots
- minting `https://app.mnemospark.ai/?code=...` share URLs after `/complete`
- appearing in discovery/search surfaces after the first settlement

## Prerequisites

- Deployed `mnemospark-backend` with the mnemospark-lite routes enabled:
  - `POST /api/mnemospark-lite/upload`
  - `POST /api/mnemospark-lite/upload/complete`
  - `GET /api/mnemospark-lite/uploads`
  - `GET /api/mnemospark-lite/download/{uploadId}`
  - `POST /api/mnemospark-lite/share`
  - `POST /api/mnemospark-lite/shares/exchange`
  - `POST /api/mnemospark-lite/delete`
- CDP facilitator auth configured (Lambda env `CDP_API_KEY_SECRET`).
- Public base URL configured (Lambda env `MNEMOSPARK_LITE_PUBLIC_BASE_URL`) so the x402 `resource` field
  matches the externally reachable API origin used for discovery.
- Payment recipient configured (stack params / env):
  - `MNEMOSPARK_RECIPIENT_WALLET`
  - `MNEMOSPARK_PAYMENT_NETWORK` (CAIP-2, e.g. `eip155:8453`)
  - `MNEMOSPARK_PAYMENT_ASSET` (USDC contract address for the network)

## 1) First paid call (triggers indexing)

Make a paid call using an x402-capable client (recommended) or a wallet flow that can supply the `PAYMENT-SIGNATURE` / `X-PAYMENT` header payload.

Request body example:

```json
{
  "filename": "hello.txt",
  "contentType": "text/plain",
  "tier": "10mb",
  "size_bytes": 12
}
```

Expected response:

- `success: true`
- `data.uploadId`
- `data.uploadUrl` (presigned PUT)
- `data.completion_token`
- `data.list_scope_bearer`
- `data.publicUrl` / `data.siteUrl` are `null` (two-step flow)
- `metadata.payment.transactionHash` is `null` (settlement happens during `/complete`)

## 2) Upload bytes (PUT to presigned URL)

PUT the file bytes to `data.uploadUrl`.

## 3) Complete + mint share URL

Call `POST /api/mnemospark-lite/upload/complete` with:

```json
{
  "uploadId": "<uploadId>",
  "completion_token": "<completion_token>"
}
```

Expected response:

- `success: true`
- `data.upload.publicUrl` is now a `https://app.mnemospark.ai/?code=...` URL
- `data.upload.status` is `uploaded`
- `data.upload.actualSize` matches the object size

## 4) Verify list + detail APIs

- `GET /api/mnemospark-lite/uploads` with header `Authorization: Bearer <list_scope_bearer>`
- `GET /api/mnemospark-lite/download/<uploadId>` with the same bearer

Expected:

- Only uploads for the payer wallet are returned
- `downloadUrl` (presigned GET) is present once `status=uploaded`

## 5) Verify 24-hour share URL + exchange

The `publicUrl` minted by `/upload/complete` is a one-time `?code=` exchange into a short-lived browser session.
For a 24-hour shareable link, use `/api/mnemospark-lite/share` (owner-scoped), then redeem via `/shares/exchange`.

### 5a) Mint share URL (owner)

```bash
curl "${MNEMOSPARK_API_BASE_URL}/api/mnemospark-lite/share" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <list_scope_bearer>" \
  -d '{"uploadId":"<uploadId>"}'
```

Response includes:

- `data.shareUrl` like `https://app.mnemospark.ai/mnemospark-lite/?share=...`
- `data.expiresAt` (24 hours)

### 5b) Exchange share token (public)

```bash
curl "${MNEMOSPARK_API_BASE_URL}/api/mnemospark-lite/shares/exchange" \
  -H "Content-Type: application/json" \
  -d '{"share_token":"<token from shareUrl>"}'
```

Response includes:

- `data.downloadUrl` (short-lived presigned GET)

## 6) Verify delete

```bash
curl "${MNEMOSPARK_API_BASE_URL}/api/mnemospark-lite/delete" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <list_scope_bearer>" \
  -d '{"uploadIds":["<uploadId>"]}'
```

Re-run `GET /api/mnemospark-lite/uploads` to confirm the upload no longer appears.

## 7) Verify discovery + search surfaces

After the first successful settle:

- CDP discovery resources should include the resource registered under your `payTo`:
  - `GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources`
- Search should surface the service after indexing completes.

Notes:

- Indexing is not necessarily immediate; allow for propagation delay.
- If the resource is missing, re-check the payment recipient address and that settle succeeded.


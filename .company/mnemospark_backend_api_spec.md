# mnemospark-backend API specification

**Version:** 1.0  
**Last updated:** February 2026  
**Audience:** Engineering, integration, API consumers

This document defines the **mnemospark-backend** REST API contract: one internet-facing API (API Gateway) with path-based routing to Lambda functions. See [mnemospark_full_workflow.md](./mnemospark_full_workflow.md) for workflow context and [mnemospark_PRD.md](./mnemospark_PRD.md) for requirements.

---

## 1. Base URL and authentication

- **Base URL:** Single API Gateway base URL (e.g. `https://{api-id}.execute-api.{region}.amazonaws.com/{stage}`). All paths are relative to this base.
- **Authentication:** **API key** (proxy/server-to-backend). Same pattern as [examples/data-transfer-cost-estimate-api](../examples/data-transfer-cost-estimate-api): API Gateway is configured with `ApiKeyRequired: true` and a usage plan.
  - **Header:** `x-api-key: <api-key-value>` (required on every request).
  - Keys are created and managed in API Gateway (e.g. Usage Plan + API Key). Clients (mnemospark-proxy) obtain the key via deployment/config. **mnemospark proxy runs on port 7120** (default) on the client/OpenClaw side; it forwards requests to this backend API.
- **CORS:** Allow origins as configured (e.g. `*` for server-to-server). Allowed headers must include at least: `Content-Type`, `x-api-key`, `Idempotency-Key` (for `POST /storage/upload`), **`PAYMENT-SIGNATURE`**, **`PAYMENT-RESPONSE`** (and legacy **`x-payment`**, **`x-payment-required`**, **`x-payment-response`** if clients send them). Allowed methods: `GET`, `POST`, `DELETE`, `OPTIONS`.

---

## 2. x402 contract (402 Payment Required)

Endpoints that require payment (e.g. upload, download, list when paid) use the **x402** protocol. Mnemospark aligns with **x402 v2**; legacy header names are accepted for backward compatibility.

**Preferred (v2):**

| Role            | Header              | When                                                                                       |
| --------------- | ------------------- | ------------------------------------------------------------------------------------------ |
| Server → client | `PAYMENT-REQUIRED`  | 402 response: payment requirements (amount, payTo, asset, network) as base64-encoded JSON. |
| Client → server | `PAYMENT-SIGNATURE` | Retry after 402: signed payment payload (base64).                                          |
| Server → client | `PAYMENT-RESPONSE`  | 200 response: settlement details (optional).                                               |

**Legacy (accepted):** `x-payment-required` (402), `x-payment` or `X-PAYMENT` (retry), `x-payment-response` (200). Sellers may send both v2 and legacy; clients should accept either.

**Network:** Use **CAIP-2** identifiers (e.g. Base mainnet **`eip155:8453`**, Base Sepolia **`eip155:84532`**).

**Backend behavior:** When returning 402, send at least one of `PAYMENT-REQUIRED` or `x-payment-required`. When reading payment on retry, accept `PAYMENT-SIGNATURE` or `X-PAYMENT` / `x-payment`.

---

## 3. General request / response conventions

- **Content-Type:** `application/json` for all JSON request and response bodies. Exceptions:
  - **Upload (inline):** If the API accepts file content in the request body (small files), the body may be JSON with a base64 field or multipart (see Outstanding questions).
  - **Download:** For **large files**, the response is JSON containing a **presigned URL**; the actual file is retrieved with `GET <presigned-url>` (binary, from S3). For **small files**, the backend may return JSON with base64 `content` or a presigned URL (see §7).
- **Character encoding:** UTF-8.
- **Error body:** All error responses use a common JSON shape (see §10).

---

## 4. Path and method summary

| Method        | Path                 | Lambda                       | Description                                                                                              |
| ------------- | -------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------- |
| POST          | `/estimate/storage`  | S3 storage cost              | BCM-based storage cost estimate (GB, region).                                                            |
| POST          | `/estimate/transfer` | Data transfer cost           | BCM-based data transfer cost estimate (direction, GB, region).                                           |
| POST          | `/price-storage`     | Price-storage (orchestrator) | Storage + transfer cost + markup; create quote in DynamoDB (1h TTL).                                     |
| POST          | `/storage/upload`    | Upload                       | Quote lookup, payment verification, then upload (inline or presigned URL). **Supports Idempotency-Key.** |
| GET / POST    | `/storage/ls`        | Object storage               | List object metadata (name + size) for one key.                                                          |
| GET / POST    | `/storage/download`  | Object storage               | Get object (presigned URL for large files; optional inline for small).                                   |
| POST / DELETE | `/storage/delete`    | Object storage               | Delete object (and bucket if empty).                                                                     |

---

## 5. Cost and quote endpoints

### 5.1 `POST /estimate/storage`

S3 storage cost only (BCM Pricing Calculator). Design pattern: [examples/s3-cost-estimate-api](../examples/s3-cost-estimate-api).

**Request (query or JSON body):**

| Field    | Type   | Required | Description                                                                                                |
| -------- | ------ | -------- | ---------------------------------------------------------------------------------------------------------- |
| gb       | number | Yes      | Storage size in GB (e.g. 100).                                                                             |
| region   | string | No       | AWS region (default `us-east-1`).                                                                          |
| rateType | string | No       | `BEFORE_DISCOUNTS` \| `AFTER_DISCOUNTS` \| `AFTER_DISCOUNTS_AND_COMMITMENTS` (default `BEFORE_DISCOUNTS`). |

**Response 200 (JSON):**

| Field          | Type   | Description               |
| -------------- | ------ | ------------------------- |
| estimatedCost  | number | Cost in USD.              |
| currency       | string | e.g. `USD`.               |
| storageGbMonth | number | Echo of request gb.       |
| region         | string | Echo of request region.   |
| rateType       | string | Echo of request rateType. |

---

### 5.2 `POST /estimate/transfer`

Data transfer (egress/ingress) cost only (BCM). Design pattern: [examples/data-transfer-cost-estimate-api](../examples/data-transfer-cost-estimate-api).

**Request (query or JSON body):**

| Field     | Type   | Required | Description                       |
| --------- | ------ | -------- | --------------------------------- |
| direction | string | No       | `in` \| `out` (default `in`).     |
| gb        | number | No       | Data size in GB (default 100).    |
| region    | string | No       | AWS region (default `us-east-1`). |
| rateType  | string | No       | Same as /estimate/storage.        |

**Response 200 (JSON):**

| Field         | Type   | Description                |
| ------------- | ------ | -------------------------- |
| estimatedCost | number | Cost in USD.               |
| currency      | string | e.g. `USD`.                |
| dataGb        | number | Echo of request gb.        |
| direction     | string | Echo of request direction. |
| region        | string | Echo of request region.    |
| rateType      | string | Echo of request rateType.  |

---

### 5.3 `POST /price-storage`

Orchestrator: calls storage + transfer cost, adds markup, creates quote in DynamoDB (1h TTL). Returns quote for use in upload.

**Request (JSON body):**

| Field          | Type   | Required | Description                                 |
| -------------- | ------ | -------- | ------------------------------------------- |
| wallet_address | string | Yes      | Agent wallet address (Base).                |
| object_id      | string | Yes      | From backup command (e.g. tar.gz filename). |
| object_id_hash | string | Yes      | SHA-256 hash of object (from backup).       |
| gb             | number | Yes      | Object size in GB.                          |
| provider       | string | Yes      | MVP: `aws`.                                 |
| region         | string | Yes      | AWS region (e.g. `us-east-1`).              |

**Response 200 (JSON):**

| Field          | Type   | Description                                |
| -------------- | ------ | ------------------------------------------ |
| timestamp      | string | e.g. `YYYY-MM-DD HH:MM:SS`.                |
| quote_id       | string | Quote identifier (valid 1 hour).           |
| storage_price  | number | Total price (storage + transfer + markup). |
| addr           | string | Echo wallet_address.                       |
| object_id      | string | Echo object_id.                            |
| object_id_hash | string | Echo object_id_hash.                       |
| object_size_gb | number | Echo gb.                                   |
| provider       | string | Echo provider.                             |
| location       | string | Echo region.                               |

---

## 6. Upload: `POST /storage/upload`

Quote lookup, payment verification (EIP-712/USDC), then upload to S3 (bucket per wallet, client-held encryption). Logs transaction in DynamoDB.

**Required headers:**

| Header          | Description                                                                    |
| --------------- | ------------------------------------------------------------------------------ |
| x-api-key       | API key (all requests).                                                        |
| Idempotency-Key | Optional but **recommended**. Opaque token (e.g. UUID) for the upload. See §9. |

**Request (JSON body):** At minimum, the proxy must send quote and payment context; exact payload is partially **outstanding** (see §11).

| Field          | Type   | Required          | Description                                                                                                                                                                                                                                                                                                                                                  |
| -------------- | ------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| quote_id       | string | Yes               | From price-storage response.                                                                                                                                                                                                                                                                                                                                 |
| wallet_address | string | Yes               | Agent wallet address.                                                                                                                                                                                                                                                                                                                                        |
| object_id      | string | Yes               | From backup.                                                                                                                                                                                                                                                                                                                                                 |
| object_id_hash | string | Yes               | From backup.                                                                                                                                                                                                                                                                                                                                                 |
| (payment)      | —      | Yes               | **Outstanding:** EIP-712 payment authorization — placement (header vs body) and exact shape TBD. See [clawrouter_wallet_gen_payment_eip712.md](./clawrouter_wallet_gen_payment_eip712.md).                                                                                                                                                                   |
| (file content) | —      | Context-dependent | **Outstanding:** For **large files (e.g. up to 50 GB)** the backend must **not** receive the file in the request (API Gateway and Lambda payload limits). Use **presigned PUT URL** flow: backend returns a presigned S3 PUT URL; client uploads the file directly to S3. For **small files**, inline options (e.g. JSON `content` base64 or multipart) TBD. |

**Response 200 (JSON):**

| Field         | Type   | Description                             |
| ------------- | ------ | --------------------------------------- |
| quote_id      | string | Echo.                                   |
| addr          | string | Wallet address.                         |
| addr_hash     | string | Wallet hash.                            |
| trans_id      | string | On-chain transaction id.                |
| storage_price | number | Amount charged.                         |
| object_id     | string | Echo.                                   |
| object_key    | string | S3 object key (for ls/download/delete). |
| provider      | string | e.g. `aws`.                             |
| bucket_name   | string | S3 bucket name.                         |
| location      | string | Region.                                 |

For **presigned URL** flow, an intermediate response may include e.g. `upload_url` (presigned PUT) and `object_key`; client PUTs the file to `upload_url`, then may call a completion endpoint or backend treats S3 upload as completion (implementation detail).

---

## 7. Download: `GET /storage/download` or `POST /storage/download`

Get object from S3 (decrypt if client-held encryption). Supports **small (e.g. ≤10 MB)** and **large (e.g. up to 50 GB)** files.

**Best practice (AWS):** API Gateway and Lambda have payload limits (~6 MB Lambda sync, ~10 MB API Gateway). For **large files**, the backend must **not** stream the full response through Lambda. Use **presigned GET URL**:

- Client calls `GET /storage/download?wallet_address=...&object_key=...&location=...` (or POST with JSON body).
- Backend validates auth, then returns **JSON** with a **presigned GET URL** (and optional expiry).
- Client performs `GET <presigned-url>` to S3 to receive the **binary** file (e.g. `Content-Type: application/octet-stream` or object's content type).

For **small files**, implementations may optionally return the file **inline** (e.g. JSON `{ "content": "<base64>" }` or a small binary response with response streaming) for convenience; the spec **recommends presigned URL for all sizes** for consistency and to avoid Lambda/API Gateway size limits.

**Request (query for GET, or JSON body for POST):**

| Field          | Type   | Required | Description                            |
| -------------- | ------ | -------- | -------------------------------------- |
| wallet_address | string | Yes      | Wallet address.                        |
| object_key     | string | Yes      | S3 object key.                         |
| location       | string | No       | AWS region (default e.g. `us-east-1`). |

**Response 200 — presigned URL (recommended):**

| Field              | Type   | Description                                         |
| ------------------ | ------ | --------------------------------------------------- |
| download_url       | string | Presigned GET URL for S3 (single use or short TTL). |
| object_key         | string | Echo.                                               |
| expires_in_seconds | number | Optional. URL validity.                             |

Client then: `GET <download_url>` → binary body (file). Content-Type from S3 or `application/octet-stream`.

**Response 200 — inline (optional, small files only):**

If backend supports inline for small objects (e.g. < 5 MB):

| Field      | Type   | Description                |
| ---------- | ------ | -------------------------- |
| object_key | string | Echo.                      |
| content    | string | Base64-encoded file bytes. |
| bucket     | string | Bucket name.               |

---

## 8. List and delete

### 8.1 `GET /storage/ls` or `POST /storage/ls`

List one object's metadata (name + size).

**Request:** Query (GET) or JSON body (POST): `wallet_address`, `object_key`, optional `location`.

**Response 200 (JSON):**

| Field      | Type    | Description  |
| ---------- | ------- | ------------ |
| success    | boolean | true.        |
| key        | string  | Object key.  |
| size_bytes | number  | Object size. |
| bucket     | string  | Bucket name. |

---

### 8.2 `POST /storage/delete` or `DELETE /storage/delete`

Delete object; delete bucket if empty.

**Request:** Query or JSON body: `wallet_address`, `object_key`, optional `location`.

**Response 200 (JSON):**

| Field          | Type    | Description                 |
| -------------- | ------- | --------------------------- |
| success        | boolean | true.                       |
| key            | string  | Deleted key.                |
| bucket         | string  | Bucket name.                |
| bucket_deleted | boolean | true if bucket was removed. |

---

## 9. Idempotency (`POST /storage/upload`)

**Supported operation:** `POST /storage/upload` only.

- **Header:** `Idempotency-Key: <opaque-token>` (e.g. UUID). Recommended for all uploads to support retries and avoid double charge on timeout/retry.
- **TTL:** 24 hours (server retains idempotency state for this key for 24h).
- **Behavior:**
  - **First request** with key `K`: Process upload; store result associated with `K`; return 200 + response.
  - **Duplicate request** (same `K` within TTL):
    - If upload **already completed:** Return **200** and the **same** response body (cached); no double charge, no duplicate object.
    - If upload **in progress:** Return **409 Conflict** (or **202 Accepted** with same `object_key` if backend can deduplicate); client may retry after delay.
- **Large uploads (presigned URL flow):** Idempotency key applies to the "create upload / get presigned URL" step. Same key → same presigned URL (or 200 with existing object_key if already completed). Client must use the same key when retrying after timeout.

---

## 10. Errors

All error responses use a common JSON body and appropriate HTTP status.

**Error response body (application/json):**

| Field   | Type             | Description                                                    |
| ------- | ---------------- | -------------------------------------------------------------- |
| error   | string           | Short code or message (e.g. `Bad request`, `quote_not_found`). |
| message | string           | Human-readable detail.                                         |
| details | object or string | Optional. Extra context.                                       |

**Status code mapping:**

| HTTP | When                                                      |
| ---- | --------------------------------------------------------- |
| 400  | Validation (missing/invalid params), bad payload.         |
| 402  | Payment required (if backend returns 402 before payment). |
| 404  | Quote not found, object not found.                        |
| 409  | Conflict (e.g. idempotency: upload already in progress).  |
| 500  | Internal server error.                                    |

---

## 11. Outstanding questions

These are explicitly **not** resolved in this spec; they should be decided and then this document updated.

1. **Upload payload and EIP-712 placement**
   - **Upload (small file):** How is the file sent? Options: (a) JSON body `{ "content": "<base64>" }`, (b) multipart/form-data, (c) presigned URL only (no inline).
   - **EIP-712 payment authorization:** Should it be sent in a **header** (e.g. `X-Payment-Authorization` or similar) or in the **request body**? Affects CORS and proxy implementation.

2. **Upload (large file) flow**
   - Confirm presigned PUT URL flow: (1) `POST /storage/upload` with metadata + payment + Idempotency-Key → 200 + presigned PUT URL (+ object_key); (2) client PUTs binary body to presigned URL; (3) optional "complete" call or backend infers completion from S3. Exact response shape for step (1) to be defined.

---

## 12. References

- [mnemospark_full_workflow.md](./mnemospark_full_workflow.md) — Full workflow and path-to-Lambda mapping.
- [mnemospark_PRD.md](./mnemospark_PRD.md) — Requirements and path table.
- [internet_facing_API.md](./infrastructure_design/internet_facing_API.md) — Security and API Gateway best practices.
- [clawrouter_wallet_gen_payment_eip712.md](./clawrouter_wallet_gen_payment_eip712.md) — EIP-712 payment example.
- Examples: [s3-cost-estimate-api](../examples/s3-cost-estimate-api), [data-transfer-cost-estimate-api](../examples/data-transfer-cost-estimate-api), [object-storage-management-api](../examples/object-storage-management-api).

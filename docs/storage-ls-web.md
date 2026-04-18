# ls-web storage BFF (`/storage/ls-web/*`)

Browser-oriented flow for **`https://app.mnemospark.ai`**: the CLI (or any wallet-proof client) **mints** a short-lived session; the browser **exchanges** a one-time code for an **HttpOnly** cookie; then the browser can **list** the wallet bucket and request **batch presigned downloads**. There is **no delete** route on this surface.

**OpenAPI:** `0.1.6` — see `docs/openapi.yaml`.

## Session and cookie

| Item | Value |
|------|--------|
| Session TTL | **6 hours** (21 600 seconds) from successful **mint** |
| Exchange code | High-entropy opaque string; server stores **SHA-256** only; **single-use** |
| Session cookie name | **`mnemospark_ls_web`** |
| Cookie attributes | `HttpOnly`, `Secure`, `Path=/`. **`Domain`** / **`SameSite`** come from Lambda env (see `template.yaml`). **Production:** `Domain=.mnemospark.ai`, `SameSite=Lax`. **Staging (execute-api URL):** `LS_WEB_COOKIE_DOMAIN=host-only` (omit `Domain=`) and `SameSite=None`—many browsers still block or partition these cross-site cookies, so QA against the raw execute-api URL is unreliable. **Recommended:** map a hostname under **`mnemospark.ai`** (for example **`staging.api.mnemospark.ai`**) to the staging API and use the same **`Domain=.mnemospark.ai`** + **`Lax`** pattern as production. |
| DynamoDB | Table `LS_WEB_SESSION_TABLE_NAME`; PK `session_id`; GSI **`GsiExchangeCode`** on `exchange_code_hash`; TTL attribute **`expires_at`** |

## CORS and credentials

Responses from **exchange**, **list**, and **download** include:

- `Access-Control-Allow-Origin: https://app.mnemospark.ai` (overridable via Lambda env `MNEMOSPARK_LS_WEB_CORS_ORIGIN`)
- `Access-Control-Allow-Credentials: true`

**Preflight:** API Gateway’s stage-level CORS must allow credentialed browser calls. If `RestApiCorsAllowOrigin` is `*`, some browsers will reject credentialed `fetch` to these routes. For production, set stack parameter **`RestApiCorsAllowOrigin`** to include **`https://app.mnemospark.ai`** (exact) or another explicit HTTPS origin policy your deployment uses. The REST API **AllowHeaders** list includes **`Cookie`** for cookie-based session calls.

## Rate limiting

**Exchange** and **download** are sensitive to abuse. Prefer **AWS WAF** rate-based rules on `/storage/ls-web/exchange` and `/storage/ls-web/download`, and/or account-level throttling. Stage defaults already apply API Gateway method throttling (see `template.yaml` `MethodSettings`).

## Endpoints

### `POST /storage/ls-web/session` (wallet authorizer)

Optional JSON body: `{ "location": "us-east-1" }` for S3 region (defaults to Lambda region).

**200** example:

```json
{
  "success": true,
  "code": "<single-use-secret>",
  "app": "https://app.mnemospark.ai/?code=<url-encoded-code>",
  "expires_at": "2026-04-17T12:00:00Z"
}
```

Mint from CLI/proxy: same **`X-Wallet-Signature`** header as `POST /storage/ls`; signed **`path`** must be **`/storage/ls-web/session`** and **`method`** **`POST`**.

### `POST /storage/ls-web/exchange` (no wallet header)

JSON body: `{ "code": "<otp>" }`.

**200:** JSON `{ "success": true }` and **`Set-Cookie`** for `mnemospark_ls_web`. Replaying the same code returns **401** `invalid_or_expired_code`.

### `POST /storage/ls-web/list` (session cookie)

Optional body matches list mode pagination: `continuation_token`, `max_keys` (1–1000), `prefix`, optional `location` override.

Response matches **`POST /storage/ls`** list mode (`success`, `list_mode`, `bucket`, `objects[]` with `key`, `size_bytes`, `last_modified`, pagination fields).

### `POST /storage/ls-web/download` (session cookie)

JSON body:

```json
{
  "object_keys": ["file-a", "file-b"],
  "expires_in_seconds": 300
}
```

- **At most 25** keys per request.
- Each key must be a **single path segment** (same rule as `/storage/download`).
- **`expires_in_seconds`** optional, 1–3600 (default from `STORAGE_DOWNLOAD_URL_TTL_SECONDS`, same as `/storage/download`).

**200** body:

```json
{
  "success": true,
  "results": [
    { "object_key": "file-a", "url": "https://...", "expires_at": "2026-04-17T12:05:00Z" },
    { "object_key": "missing", "error": "object_not_found", "message": "Object not found: missing." }
  ]
}
```

## CSRF

**Production** uses **`SameSite=Lax`** plus **POST** for exchange, list, and download (same-site between `app` and `api` under `mnemospark.ai`). **Staging** uses **`SameSite=None`** only so the session cookie is sent on cross-site `fetch` to the execute-api URL; keep exchange/list/download on **POST** and treat the shell as a trusted client surface.

## Related

- Wallet proof: `meta_docs/wallet-proof.md` (in mnemospark-docs repo)
- `docs/storage-ls.md` — list/stat semantics for `/storage/ls`
- `docs/openapi.yaml` — formal schemas and errors

# Logging and observability conventions

This backend uses structured JSON logs for all internet-facing Lambda handlers
and the wallet authorizer. Each log record must be JSON-serializable and include
an `event` field.

## Event naming

- Use concise snake_case event names, for example:
  - `price_request_parsed`
  - `upload_request_parsed`
  - `payment_settlement_succeeded`
  - `storage_download_not_found`
  - `storage_delete_internal_error`
  - `authorizer_debug_decision`

## Core fields

When available, include these core fields in request lifecycle logs:

- `request_id` (API Gateway request ID when present)
- `method`
- `path`
- `status` (final HTTP status for result/error events)
- `wallet_address`
- `quote_id`
- `trans_id`
- `error_code`
- `error_message` (concise, no secrets)

`services/common/api_call_logger.py` writes these fields to both:

- CloudWatch (`event=api_call_logged`)
- DynamoDB `${StackName}-api-calls`

The wallet authorizer writes best-effort decision events to:

- CloudWatch (`authorizer_debug_*`)
- DynamoDB `${StackName}-wallet-auth-events`

## Sensitive-data rules

Never log:

- private keys
- raw signatures
- ciphertext payloads
- wrapped DEKs
- secret payloads or secret material from Secrets Manager

Failure logs should use concise error codes/messages and avoid raw request
payload dumps.

## Investigation correlation flow

For an incident involving one API request:

1. Start from API Gateway access logs (`requestId`, method, route, status).
2. Find wallet authorizer logs and `wallet-auth-events` entries by:
   - `request_id`
   - `method` + `path`
   - `resource_arn`
3. Find handler logs and `api-calls` entry by:
   - `request_id`
   - `wallet_address`
   - `quote_id` / `trans_id`
4. Correlate billing/storage state from:
   - `${StackName}-payments` (payment ledger)
   - `${StackName}-upload-transaction-log` (object/payment linkage)
5. Use CloudTrail (`${StackName}-cloudtrail`) for account-level timeline and
   API management events around the same time window.

Note: the current template enables CloudTrail management events. If DynamoDB or
S3 data-event correlation is required for a deeper audit trail, enable data
event selectors for those resources.

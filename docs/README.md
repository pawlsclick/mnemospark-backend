# mnemospark-backend API docs

`docs/openapi.yaml` is the canonical API contract for mnemospark-backend.

Current deployed paths are unversioned, but they are treated as **v1 semantics**
for compatibility and future versioned routing work.

Production backend implementation lives in `template.yaml` and `services/`.
Legacy proofs-of-concept are archived under `archive/examples/` and are not part
of the supported API surface documented here.

## Public endpoint inventory

The current internet-facing API Gateway routes are:

- `POST /price-storage`
- `POST /payment/settle` (quote settlement after price-storage, or monthly **renewal** without a new quote; see [payment-settle.md](payment-settle.md))
- `POST /storage/upload`
- `POST /storage/upload/confirm`
- `GET /storage/ls`
- `POST /storage/ls`
- `GET /storage/download`
- `POST /storage/download`
- `DELETE /storage/delete`
- `POST /storage/delete`

There are no additional public routes at this time; scheduled/internal functions
(for example storage housekeeping and [Base relayer monitoring](base-relayer-monitoring.md))
are not part of the public API contract. When housekeeping runs in **renewal calendar**
mode, it enforces payment by querying active inventory and renewal rows (UTC billing month),
rather than scanning upload logs on a fixed day interval.

## Observability conventions

- `docs/logging-observability.md` defines structured logging fields and
  investigation correlation flow across CloudWatch, DynamoDB log tables, and
  CloudTrail.

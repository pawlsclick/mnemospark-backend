# mnemospark-backend API docs

`docs/openapi.yaml` is the canonical API contract for mnemospark-backend.

Current deployed paths are unversioned, but they are treated as **v1 semantics**
for compatibility and future versioned routing work.

## Public endpoint inventory

The current internet-facing API Gateway routes are:

- `POST /price-storage`
- `POST /storage/upload`
- `POST /storage/upload/confirm`
- `GET /storage/ls`
- `POST /storage/ls`
- `GET /storage/download`
- `POST /storage/download`
- `DELETE /storage/delete`
- `POST /storage/delete`

There are no additional public routes at this time; scheduled/internal functions
(for example storage housekeeping) are not part of the public API contract.

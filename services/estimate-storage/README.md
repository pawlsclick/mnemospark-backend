# mnemospark estimate/storage Lambda

This service implements `POST /estimate/storage` (and `GET` for compatibility) for the mnemospark backend API.

## API contract

- Request input (query string or JSON body):
  - `gb` (required)
  - `region` (optional, default `us-east-1`)
  - `rateType` (optional, default `BEFORE_DISCOUNTS`)
- Response JSON:
  - `estimatedCost`
  - `currency`
  - `storageGbMonth`
  - `region`
  - `rateType`

## Infrastructure integration point

The route is wired in the repository root `template.yaml`:

- `GET /estimate/storage`
- `POST /estimate/storage`

Both events are mapped to `EstimateStorageFunction` (`services/estimate-storage/app.py`).

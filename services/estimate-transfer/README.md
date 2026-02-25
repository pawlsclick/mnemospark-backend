# mnemospark estimate/transfer Lambda

This service implements `POST /estimate/transfer` (and `GET` for compatibility) for the mnemospark backend API.

## API contract

- Request input (query string or JSON body):
  - `direction` (optional, `in` or `out`, default `in`)
  - `gb` (optional, default `100`)
  - `region` (optional, default `[REDACTED]`)
  - `rateType` (optional, default `BEFORE_DISCOUNTS`)
- Response JSON:
  - `estimatedCost`
  - `currency`
  - `dataGb`
  - `direction`
  - `region`
  - `rateType`

## Infrastructure integration point

The route is wired in the repository root `template.yaml`:

- `GET /estimate/transfer`
- `POST /estimate/transfer`

Both events are mapped to `EstimateTransferFunction` (`services/estimate-transfer/app.py`).

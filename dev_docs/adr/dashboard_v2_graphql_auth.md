# ADR: Dashboard v2 GraphQL access (internal)

## Context

Dashboard v2 needs a read-only GraphQL API isolated from the public wallet-proof REST API. The unified plan requires that the GraphQL transport not be anonymously exposed on the public internet.

## Decision

- **API shape:** Separate **API Gateway HTTP API** (`AWS::Serverless::HttpApi`) with `POST /graphql` and `OPTIONS /graphql` for CORS preflight.
- **Authorization:** **IAM (SigV4)** is enabled as the default authorizer (`EnableIamAuthorizer: true`, `DefaultAuthorizer: AWS_IAM`). Clients must sign requests with AWS credentials that are allowed to invoke the API (for example an IAM role used by a Next.js server route or other internal caller).
- **CORS:** Lambda returns `Access-Control-Allow-*` headers for browser preflight and cross-origin calls when a BFF proxies with SigV4.

## Consequences

- Browsers do not call this API with long-lived access keys; use a **server-side** proxy (or another short-lived credential path per org policy).
- OpenAPI documents this surface under **`dashboardGraphqlHttpApi`** servers with **`dashboardAwsIam`** security (not `walletProof`).

## Status

Accepted for phase 1 (minimal schema + `revenueSummary`). Revisit for API keys, private APIs, or VPC endpoints if deployment constraints require it.

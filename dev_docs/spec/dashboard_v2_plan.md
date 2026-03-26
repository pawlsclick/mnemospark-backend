# Dashboard v2 — Unified implementation plan (two repos)

**Status:** Executable plan for Cursor Cloud agents (one repo per agent)  
**Canonical location:** `mnemospark-ops/dev_docs/spec/dashboard_v2_plan.md`  

**Copy for backend work:** Duplicate this file into `mnemospark-backend/dev_docs/` (or open the same path via submodule / raw fetch) so an agent with **only** `mnemospark-backend` checked out has the full plan. Keep both copies aligned when the plan changes.

**Product intent:** `dev_docs/feature/dashboard_v1.md` — internal Ops Console (sales, ops, wallets, transactions, events, trace), read-only.

**Frontend location (mnemospark-ops only):** `dashboard_v2/` at the **repository root** (sibling to `dashboard/`, not nested inside it).

---

## Executive summary

| Topic | Decision |
| --- | --- |
| API placement | **Option A — fixed:** New **GraphQL** surface in **`mnemospark-backend`** only |
| Risk to existing API | **Zero breaking change** — additive SAM resources; **do not** modify existing `AWS::Serverless::Api` paths, Lambdas, or authorizers |
| Frontend | **`mnemospark-ops/dashboard_v2/`** — Next.js + Apollo Client + GraphQL Codegen |
| Backend | New **Lambda** + **separate** API Gateway (HTTP API or REST **not** shared with current customer REST API) |
| Data access | **Read-only** DynamoDB IAM; resolver code in new modules; optional reuse of **read** helpers only |
| HTTP contract docs | **OpenAPI v3.2** — any new **HTTP** surface (including GraphQL transport) is documented in **`docs/openapi.yaml`**, following the same structure and quality bar as existing paths (see **`docs/README.md`**) |

---

## Part A — Zero-risk Option A (backend architecture)

### A.1 Principles (non-negotiable)

1. **Additive-only CloudFormation/SAM:** New `Resources` blocks only. No edits to existing function **handler entry points** unless you are **extracting shared read-only libraries** and prove parity with tests.
2. **Separate API:** The production REST API (`AWS::Serverless::Api` / existing stage) **must not** gain new paths for GraphQL. Deploy a **second** API Gateway resource (recommended: **HTTP API** `AWS::ApiGatewayV2::Api` for cost/simplicity, or a second `AWS::Serverless::Api` dedicated to internal GraphQL).
3. **Single purpose Lambda:** One (or a small set of) **new** function(s) whose **only** job is GraphQL execution (and optional future dashboard-only concerns). Do **not** attach GraphQL to existing user-facing Lambdas.
4. **Read-only data plane:** IAM policy allows **only** DynamoDB read actions required for dashboard queries. **Deny** writes at policy level for this role.
5. **No table schema breakage:** Dashboard reads **existing** tables as they are today. Normalization belongs in **resolver/domain** code, not DynamoDB key redesign.

### A.2 Recommended stack (GraphQL on Lambda)

- **Runtime:** Match stack: **Python 3.13** (same as `template.yaml` Globals).
- **GraphQL library:** e.g. **Strawberry** or **Ariadne** (evaluate bundle size, cold start; pin versions).
- **Transport:** `POST /graphql` with JSON body `{"query","variables"}`; optional `GET` only if you implement persisted queries later (not required for v1).
- **Why not AppSync for v2.0:** AppSync is valid and isolated, but adds **second** operational surface (data sources, mapping templates). **HTTP API + Lambda** keeps everything in Python alongside existing patterns. Revisit AppSync if you need subscriptions later.

### A.3 AWS resources to add (checklist)

Use **AWS Serverless Application Model** (`template.yaml`) additions:

| Resource | Purpose |
| --- | --- |
| `DashboardGraphQLFunction` | `AWS::Serverless::Function` — GraphQL handler |
| `DashboardGraphQLApi` | **New** `AWS::ApiGatewayV2::Api` (HTTP API) **or** new `AWS::Serverless::Api` **not** merged with existing API |
| `DashboardGraphQLIntegration` + routes | `POST /graphql` (and `OPTIONS` for CORS if browser calls directly) |
| `AWS::Lambda::Permission` | Allow API Gateway to invoke **only** `DashboardGraphQLFunction` |
| `AWS::Logs::LogGroup` | Optional explicit log retention for dashboard Lambda (align with `ObservabilityLogRetentionDays`) |
| Outputs | Export **HTTPS URL** of the new API stage for `dashboard_v2` env |

**Do not:** Add dashboard routes to the existing `ServerlessRestApi` resource that serves customer traffic.

**AWS documentation (validate with AWS MCP `aws___search_documentation` / `aws___call_aws` during implementation):**

- Lambda + DynamoDB least-privilege: [IAM example — Lambda access DynamoDB](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_lambda-access-dynamodb.html) — adapt to **read-only** (`GetItem`, `Query`, `BatchGetItem`, `Scan` only if unavoidable; prefer `Query` + GSIs).
- API Gateway Lambda proxy: [CloudFormation `AWS::ApiGateway::Method` — Lambda proxy](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-method.html) (HTTP API v2: [`AWS::ApiGatewayV2::Api`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigatewayv2-api.html)).
- SAM connectors (optional): [SAM connector reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/reference-sam-connector.html) if you use SAM connectors for Lambda ↔ DynamoDB wiring.

### A.4 IAM policy shape (read-only dashboard role)

Attach an **inline policy** or `AWS::IAM::Role` `Policies` on **only** `DashboardGraphQLFunction`:

- **Allow** (minimal set — tune to actual resolver needs):
  - `dynamodb:GetItem`
  - `dynamodb:Query`
  - `dynamodb:BatchGetItem`
  - `dynamodb:Scan` — **avoid** in production hot paths; use only if legacy access patterns require it, and gate with limits in code
  - `dynamodb:DescribeTable` (optional, for health)
- **Resource:** Each table ARN: `!Sub` / `!GetAtt` for **QuotesTable**, **PaymentLedgerTable**, **ApiCallsTable**, **WalletAuthEventsTable**, **UploadTransactionLogTable**, **UploadIdempotencyTable**, etc. — **exact** logical IDs from current `template.yaml`.
- **Explicitly omit:** `PutItem`, `UpdateItem`, `DeleteItem`, `BatchWriteItem`, `TransactWriteItems`, `dynamodb:*` wildcards on `*`.

**CloudWatch Logs:** Include standard `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` on `arn:aws:logs:${Region}:${Account}:log-group:/aws/lambda/...` (SAM often injects via `AWS::Lambda::Function` default role — verify generated policy).

**Optional read-only KMS:** If any table uses customer-managed CMK, add `kms:Decrypt` on that key for reads.

**Validation step for agents:** After deploy, run a test `Query` that touches each table; confirm **no** `AccessDenied` in CloudWatch. Use AWS MCP to cross-check policy examples if errors appear.

### A.5 Network and auth (internal)

- **Default:** API is **regional**; protect with **IAM auth** (SigV4), **private API + VPC endpoint**, or **API key + resource policy** — pick one and document in ADR. **Do not** expose unauthenticated GraphQL to the public internet.
- **Browser → GraphQL:** If the dashboard calls from the browser, use a **short-lived** credential path (Cognito/IAM Identity Center) or **server-side BFF** in Next.js that holds secrets — **never** embed long-lived AWS keys in `dashboard_v2`. Preferred for internal: **Next.js server components / route handlers** proxy to GraphQL with AWS SigV4 using task role in Cursor Cloud, or **VPN-only** + API key.

### A.6 Repository layout (mnemospark-backend)

Suggested (adjust names to taste):

```
services/
  dashboard_graphql/
    app.py                 # Lambda handler: Mangum/awsgi or API Gateway event adapter
    schema.py              # GraphQL schema
    resolvers/             # Field resolvers
    domain/                # Read services (DynamoDB access, caps, pagination)
```

- **Shared code:** Prefer **new** `domain/read_*.py` modules. Refactor existing handlers to call shared readers **only** when it reduces duplication **without** behavior change.

### A.7 OpenAPI v3.2 documentation (required for new HTTP APIs)

The backend treats **`docs/openapi.yaml`** as the **canonical HTTP API contract** (`openapi: "3.2.0"`). **`docs/README.md`** describes how that spec relates to deployed routes and v1 semantics.

**Rule:** Any **new** route exposed through API Gateway for dashboard v2 (including the GraphQL **transport** at `POST /graphql`) **must** be added to **`docs/openapi.yaml`** in the same style as existing operations:

- **`tags`**, **`operationId`**, **`summary`/`description`**, **`requestBody`** / **`responses`** with **`$ref`** to **`components/schemas`** and **`components/responses`** where applicable.
- **`servers`** / path patterns consistent with the doc’s existing API Gateway URL placeholder.
- **`security`** schemes documented explicitly (dashboard auth will differ from **`walletProof`** on public routes — define a dedicated scheme, e.g. IAM, API key, or bearer, per the ADR in Part A.5).

**GraphQL note:** The **GraphQL SDL** (types, queries, mutations) remains the **authoritative GraphQL contract** for field-level typing and codegen. **OpenAPI** documents the **HTTP layer**: method, path, JSON body shape for standard GraphQL-over-HTTP (`query`, `variables`, optional `operationName`), success and error response envelopes, and auth headers. Optionally **`description`** may reference the SDL file path (e.g. `services/dashboard_graphql/schema.graphql`) for implementers.

If future dashboard-only **REST** endpoints are introduced, they follow the **same** OpenAPI 3.2 patterns and live in the **same** `docs/openapi.yaml` (or a split file **only** if the repo already establishes a multi-file pattern; today the canonical file is **`docs/openapi.yaml`**).

**Versioning:** Bump **`info.version`** in `openapi.yaml` when the documented contract changes in a material way (align with team practice for the existing spec).

### A.8 Backend agent checklist (mnemospark-backend)

1. Branch from default branch per repo policy; **no commits to `main`** if rules require feature branches.
2. Add SAM resources per §A.3; `sam validate`, `sam build`, unit tests for resolvers.
3. Implement minimal schema: `health { ok }` + one real query (e.g. `revenueSummary`) to prove end-to-end.
4. Update **`docs/openapi.yaml`** per §A.7 (new paths, components, security, **`info.version`** bump as appropriate).
5. Output GraphQL URL in stack **Outputs**; document env var name for frontend: `NEXT_PUBLIC_GRAPHQL_URL` or server-only `GRAPHQL_URL`.
6. Export **GraphQL SDL** (file or CI artifact) for codegen in `dashboard_v2`.
7. Run **integration test** against staging tables (read-only).

---

## Part B — Frontend (mnemospark-ops)

### B.1 Directory

- Path: **`mnemospark-ops/dashboard_v2/`** (repo root).
- Scaffold: Next.js (App Router), TypeScript, Tailwind v4, shadcn/ui, Recharts — parity with v1 `dashboard/` unless ADR says otherwise.

### B.2 Client stack

- **Apollo Client** + **GraphQL Code Generator** (`@graphql-codegen/cli`) targeting the backend SDL or introspection endpoint.
- **HTTP transport and auth:** Align with **`mnemospark-backend/docs/openapi.yaml`** for the documented `POST /graphql` operation (headers, security scheme, response envelopes). GraphQL field types remain defined by the SDL, not OpenAPI.
- **No** `@aws-sdk/*` for product data in the browser bundle.
- **Env:** `GRAPHQL_ENDPOINT` (and auth-related vars per Part A.5). Use `.env.local` (gitignored).

### B.3 Frontend agent checklist (mnemospark-ops)

1. Create `dashboard_v2/` app; copy **design tokens / AppShell** patterns from `dashboard/` incrementally.
2. Wire Apollo Provider; implement Overview page with **one** query + loading/error UI.
3. Add CI: `npm run lint`, `npm run build`, `graphql-codegen` (fail if schema drift).
4. Document in `dashboard_v2/README.md`: dependency on backend Output URL; how to run against staging; link to **`mnemospark-backend/docs/openapi.yaml`** for the HTTP contract of the GraphQL endpoint.

---

## Part C — Contract between repos (single source of truth)

| Artifact | Owner | Consumer |
| --- | --- | --- |
| GraphQL schema (`.graphql` SDL) | mnemospark-backend (generated or hand-written) | mnemospark-ops codegen |
| OpenAPI HTTP contract | **`docs/openapi.yaml`** (v3.2) | API reviewers, client generators (optional), ops runbooks; see **`docs/README.md`** |
| Endpoint URL | Backend stack Output | `dashboard_v2` env |
| Auth mechanism | Backend ADR | Frontend + deployment |

**Drift prevention:** On backend PRs, export schema; on frontend PR, codegen **must** pass. Optionally add a **pinned** schema file in `mnemospark-ops` updated by a script or copy-paste from backend releases.

---

## Part D — Product and UX (unchanged from prior plan)

- Preserve **Sales** vs **Operations** separation; reduce duplication via **fragments** and **shared widgets** (see original §4–6 in prior revision — still valid).
- Feature parity target: `dashboard_v1.md` routes and metrics.

---

## Part E — Phased delivery (cross-repo)

| Phase | Backend | Frontend |
| --- | --- | --- |
| **0** | ADR: auth + HTTP API vs REST; schema folder; OpenAPI section outline | Scaffold `dashboard_v2/`, codegen pipeline |
| **1** | Minimal schema + DynamoDB read resolvers + deploy + **`openapi.yaml`** entry for `POST /graphql` | Apollo + one page + health/revenue query |
| **2** | Full query surface for v1 parity | Port pages; fragments per widget |
| **3** | Resolver perf (pagination, limits); optional GSIs | Cache policies; E2E smoke |

---

## Part F — Success criteria

- Existing customer **REST** API behavior **unchanged** (contract tests or smoke on deploy).
- New HTTP routes are **reflected in `docs/openapi.yaml`** (OpenAPI 3.2) and described relative to **`docs/README.md`** expectations.
- Dashboard Lambda IAM is **read-only** on listed tables.
- `dashboard_v2` builds with **zero** AWS SDK data calls from the client for product reads (unless using SigV4 from server components per ADR).
- No routine **Scan** of full tables from navigation (enforce in domain layer).

---

## Part G — AWS MCP usage (mandatory for implementers)

During implementation, agents **should** use the **AWS MCP** tools (`aws___search_documentation`, `aws___call_aws` where appropriate) to:

- Confirm **SAM/CloudFormation** syntax for **HTTP API v2** + Lambda permissions.
- Validate **IAM** action lists for DynamoDB read-only patterns.
- Troubleshoot `AccessDenied` with **reference_documentation** + **troubleshooting** topics.

Local shell remains available for `sam validate` / `sam build` in the repo.

---

## References

- `dev_docs/feature/dashboard_v1.md`
- `dev_docs/spec/dashboard_spec_v10_final.md`
- **mnemospark-backend:** `docs/openapi.yaml` (canonical **OpenAPI 3.2** HTTP contract), `docs/README.md` (how the spec maps to deployed routes)
- AWS: [Lambda access DynamoDB (IAM)](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_lambda-access-dynamodb.html)
- AWS: [API Gateway Lambda proxy / HTTP API](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigatewayv2-api.html)

---

*End of unified plan.*

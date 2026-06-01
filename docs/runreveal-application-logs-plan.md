# Application logs → RunReveal (Option A)

**Status:** Phase 1 implemented in SAM (`template.yaml`, branch `feat/runreveal-app-logs-phase1`). Deploy staging first, then configure RunReveal source.  
**Chosen approach:** CloudWatch Logs → Kinesis Data Firehose → S3 → RunReveal (Generic / Custom S3).  
**Rollout:** Phased — security-critical log groups first (per eng review D1 = B).  
**Account:** `929837999468` · **Region:** `us-east-1`  
**RunReveal SNS (generic):** `arn:aws:sns:us-east-1:253602268883:runreveal_generic`  
**Prior art:** CloudTrail → S3 → RunReveal (`runreveal_cloudtrail`) merged in PR #169.

---

## Goal

Ship structured application events from `docs/logging-observability.md` (e.g. `api_call_logged`, `payment_settlement_*`, `upload_*`, `authorizer_debug_*`) into RunReveal for search and detection, **without** changing Lambda logging code or adding webhooks.

DynamoDB `${StackName}-api-calls` and `${StackName}-wallet-auth-events` stay as-is for operational queries; RunReveal is the cross-service analytics and detection layer.

---

## What already exists

| Asset | Role | Reuse for this plan |
|-------|------|---------------------|
| `services/common/api_call_logger.py` | JSON `api_call_logged` → CloudWatch + DynamoDB | **Capture only** — no code change |
| `services/common/request_log_utils.py` | `build_log_event()` fields | Field mapping reference for RunReveal |
| `template.yaml` `*FunctionLogGroup` + `ApiGatewayAccessLogsLogGroup` | 30-day retention, explicit names | **Subscription filter targets** |
| CloudTrail buckets + `Allow-RunReveal-Read` | Account audit | Pattern for app-log bucket policy |
| RunReveal sources `mnemospark-*-cloudtrail` | Management events | Separate from app logs |

**Not reused (deferred):** webhook dual-write (Option B), CloudWatch Logs export jobs for backfill, WAF logs, S3 data events on ciphertext buckets.

---

## Architecture

### Data flow (per stack: staging, then prod)

```
  Lambda / API GW
        │
        ▼
  CloudWatch Log Group  (existing)
        │
        │  Subscription filter (new, per group)
        ▼
  Kinesis Data Firehose  (new, one per stack)
        │
        │  GZIP objects, NDJSON or CWL payload
        ▼
  S3: mnemospark-{stage}-app-logs  (new bucket)
        │
        │  s3:ObjectCreated → SNS
        ▼
  SNS: runreveal_generic  (RunReveal account)
        │
        ▼
  RunReveal Custom / Generic source  (UI config)
        │
        ▼
  Detections & SQL (e.g. payment failures, 5xx spikes)
```

### ASCII — correlation with existing investigation flow

```
  User request
       │
       ├──────────────────────────────────────┐
       ▼                                      ▼
  API GW access log                    Wallet authorizer
  (JSON access format)                 (authorizer_debug_*)
       │                                      │
       └──────────────┬───────────────────────┘
                      ▼
              Handler Lambdas
              (api_call_logged + named events)
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
   CloudWatch    DynamoDB     (unchanged)
                      │
                      ▼  NEW path
              Firehose → S3 → RunReveal
```

### SAM components (planned, not implemented)

| Resource | Purpose |
|----------|---------|
| `ObservabilityAppLogsBucket` | Dedicated bucket; lifecycle to match or exceed 30d CWL retention |
| `ObservabilityAppLogsBucketPolicy` | TLS, encryption, `Allow-RunReveal-Read` for `253602268883` |
| `ObservabilityLogsFirehose` | `DirectPut` disabled; CWL subscription as source |
| `ObservabilityLogsFirehoseRole` | `logs:PutSubscriptionFilter` delivery, S3 write, optional KMS |
| `ObservabilityLogsFirehoseLogGroup` | Firehose own delivery errors |
| `ObservabilityLogsSubscriptionFilter` × N | One per targeted log group |
| `ObservabilityAppLogsBucketNotification` | `s3:ObjectCreated:*` → `runreveal_generic` |
| `MnemosparkLiteUploadFunctionLogGroup` | **Add explicit** (function exists, no LogGroup today) |
| `DiscoveryFunctionLogGroup` | **Add explicit** (same) |

**Parameters / conditions:** Reuse `IsBrowserAppStage` or new `EnableRunRevealAppLogIngest` so dev stacks do not create buckets/Firehose unless needed.

### Phase 1 log groups (security-critical)

| Log group | Log name pattern | Primary events / notes |
|-----------|------------------|-------------------------|
| `ApiGatewayAccessLogsLogGroup` | `/aws/apigateway/${StackName}-${StageName}-access` | API GW JSON access; correlate via `requestId` |
| `WalletAuthorizerFunctionLogGroup` | `/aws/lambda/${WalletAuthorizerFunction}` | `authorizer_debug_*` |
| `PaymentSettleFunctionLogGroup` | `/aws/lambda/${PaymentSettleFunction}` | `payment_settlement_*`, `api_call_logged` |
| `StorageUploadFunctionLogGroup` | `/aws/lambda/${StorageUploadFunction}` | `upload_*`, `api_call_logged` |
| `StorageDownloadFunctionLogGroup` | `/aws/lambda/${StorageDownloadFunction}` | `storage_download_*` |
| `StorageDeleteFunctionLogGroup` | `/aws/lambda/${StorageDeleteFunction}` | `storage_delete_*` |

### Phase 2 log groups (defer)

`StorageLsFunction`, `StorageLsWebFunction`, `StorageHousekeepingFunction`, `PriceStorageFunction`, `BaseRelayerMonitorFunction`, `DashboardGraphQLFunction`, `DashboardGraphQLAuthorizerFunction`, `MnemosparkLiteUploadFunction`, `DiscoveryFunction`.

### Subscription filter pattern

**Recommendation:** Empty filter (all log events) for phase 1.

- Lambda emits one JSON object per line; filtering on `"event"` in subscription filters is brittle (multi-line, START/END noise).
- Optional phase 2: metric filter or Firehose Lambda transform to drop `START RequestId` / `END RequestId` lines before S3.

### S3 layout

```
s3://mnemospark-{stage}-app-logs/
  cloudwatch-logs/
    year=YYYY/month=MM/day=DD/hour=HH/
      {firehose-delivery-id}-{sequence}.gz
```

Separate buckets per stack (staging vs prod) — mirrors CloudTrail bucket split; no cross-env mixing.

### RunReveal configuration (manual / console, after first objects land)

1. Create **Custom Source** or **Generic** source per env (e.g. `mnemospark-staging-app-logs`, `mnemospark-prod-app-logs`).
2. Point at app-log bucket; confirm SNS `runreveal_generic` subscription (same pattern as CloudTrail).
3. **Field mapping** (indicative):

| RunReveal / query field | App log JSON field |
|-------------------------|-------------------|
| `eventName` or `event` | `event` |
| `requestId` | `request_id` |
| `httpMethod` | `method` |
| `path` | `path` |
| `status` | `status` or `status_code` |
| `userIdentity` / custom | `wallet_address` |
| `errorCode` | `error_code` |

4. API Gateway access logs use **different** keys (`requestId`, `routeKey`, `status`) — either:
   - second parser / source variant, or
   - normalize in Firehose Lambda transform (phase 2).

### Security

- **No new secrets** in Lambda; read-only cross-account style for RunReveal on S3 (same as CloudTrail).
- **PII:** `wallet_address` flows to RunReveal — acceptable for security analytics; document in internal runbook.
- **Sensitive-data rules** in `logging-observability.md` unchanged; this path does not increase what leaves AWS, only duplicates CloudWatch content to S3/RunReveal.
- Firehose role: least privilege (specific bucket ARN, specific log group ARNs for subscription).

### Failure modes

| Failure | Symptom | Mitigation in plan |
|---------|---------|-------------------|
| Firehose throttling / S3 deny | Gap in RunReveal timeline | Firehose CloudWatch alarms; SAM `ObservabilityLogsFirehoseLogGroup` |
| Subscription filter mis-ARN | No data for one Lambda | Post-deploy script: list filters vs log groups |
| Wrong SNS / no notification | Objects in S3, no ingest | Verify notification config like CloudTrail buckets |
| API GW vs Lambda schema split | Broken detections on mixed fields | Phase 1: document two event families; phase 2 transform |
| CWL 30d retention < S3 lifecycle | Orphan policy | Align lifecycle ≥ 30 days |
| Large START/END noise | Noisy detections | Phase 2 transform or filter |

**Critical gap if unaddressed:** Silent Firehose failure with no alarm — plan includes delivery-failure metric alarm (P1 task).

---

## NOT in scope (this initiative)

| Item | Rationale |
|------|-----------|
| SAM deploy / `sam deploy` | User request: plan only |
| Webhook to RunReveal (Option B) | User chose Option A |
| Historical backfill of CloudWatch | Export job is separate, costly; forward-only from subscribe time |
| Replacing DynamoDB api-calls / wallet-auth-events | Operational store stays |
| WAF → `aws_waf_logs` | Follow-up TODO |
| CloudTrail S3 data events for ciphertext buckets | Separate TODO in logging doc |
| Prod promotion | Manual promote workflow after staging validation |
| RunReveal detection authoring | After ingest verified (separate step) |

---

## Code quality / SAM organization

- Add a dedicated `ObservabilityLogIngest` section in `template.yaml` (or nested stack later if template grows past comfort).
- Mirror CloudTrail `Allow-RunReveal-Read` statement id and principal — **DRY** via YAML anchor or shared condition, not copy-paste drift.
- Explicit `LogGroup` for Lite + Discovery before subscribing — avoids race with auto-created groups.

No application Python changes in Option A.

---

## Test review

### Framework

Python **pytest** — `tests/unit/`, `tests/integration/` per `AGENTS.md`. SAM validate for template changes.

### Coverage diagram (infrastructure paths)

```
CODE PATHS (new infrastructure)
[+] template.yaml — ObservabilityAppLogsBucket
  ├── [GAP] Bucket policy denies insecure transport
  ├── [GAP] RunReveal read principal present when enabled
  └── [GAP] Encryption (SSE-S3 or KMS) configured
[+] template.yaml — Firehose + IAM role
  ├── [GAP] Role trust + S3 PutObject scoped to app-log bucket
  ├── [GAP] logs:PutSubscriptionFilters on phase-1 log group ARNs only
  └── [GAP] Delivery stream has CloudWatch logging enabled
[+] template.yaml — SubscriptionFilter × 6 (phase 1)
  ├── [GAP] Each filter references correct LogGroupName + Firehose ARN
  └── [GAP] DependsOn order: LogGroup before SubscriptionFilter
[+] template.yaml — S3 → SNS notification
  ├── [GAP] TopicArn = runreveal_generic (parameterized per env)
  └── [GAP] Filter prefix/suffix matches Firehose output keys
[+] Post-deploy verification (script or runbook)
  ├── [GAP] Put test pattern in WalletAuthorizer → object in S3 within 5 min
  └── [GAP] RunReveal source shows events (manual / MCP query)

USER FLOWS (ops)
[+] Staging deploy PR merged
  └── [GAP] [→E2E] Generate traffic → confirm `api_call_logged` in RunReveal SQL
[+] Rollback
  └── [GAP] Disable subscription filters without deleting bucket (runbook)

COVERAGE: 0/12 infra paths tested (0%) — expected until implementation PR
GAPS: 12 (1 E2E ops flow)
```

### Test plan artifact location

After implementation PR: `~/.gstack/projects/mnemospark-backend/{user}-main-eng-review-test-plan-*.md` (from gstack skill).

### Planned tests (implementation PR)

| Test | Type | Assert |
|------|------|--------|
| SAM template lint/validate | CI | `sam validate --template template.yaml` |
| Unit: YAML condition `EnableRunRevealAppLogIngest` | Optional | Resources absent when false |
| Integration (staging): subscription exists | Manual/script | `aws logs describe-subscription-filters` |
| Integration: S3 object after invoke | Manual | Test Lambda invoke → gzip object under prefix |
| RunReveal query | Manual/MCP | `SELECT event, count() FROM ... WHERE event='api_call_logged' LIMIT 5` |

---

## Performance review

| Concern | Assessment |
|---------|------------|
| Volume / cost | Firehose + S3 storage; estimate from CWL **IncomingBytes** metric per phase-1 group before prod |
| Lambda cold start | **No impact** — no code change |
| API latency | **No impact** |
| Duplicate logging | CWL still primary; Firehose async — no double `PutLogEvents` |
| Filter on hot paths | Subscription is push from CWL; negligible vs handler |

**Recommendation:** Set Firehose buffer interval 60–300s and GZIP compression; review S3 lifecycle transition to IA after 30 days if cost matters.

---

## Implementation tasks

- [ ] **T1 (P1, human: ~3h / CC: ~25min)** — SAM — Add `ObservabilityAppLogsBucket` + policy + `Allow-RunReveal-Read`
  - Surfaced by: Architecture — S3 landing zone
  - Files: `template.yaml`
  - Verify: `sam validate`; policy JSON includes `253602268883`

- [ ] **T2 (P1, human: ~4h / CC: ~30min)** — SAM — Firehose delivery stream + IAM role + error log group
  - Surfaced by: Architecture — CWL → Firehose → S3
  - Files: `template.yaml`
  - Verify: `sam validate`; role policy resource ARNs scoped

- [ ] **T3 (P1, human: ~2h / CC: ~20min)** — SAM — Phase 1 subscription filters (6 log groups)
  - Surfaced by: Rollout D1-B
  - Files: `template.yaml`
  - Verify: `aws logs describe-subscription-filters` on staging

- [ ] **T4 (P1, human: ~1h / CC: ~10min)** — SAM — S3 event notification → `runreveal_generic`
  - Surfaced by: Architecture — RunReveal ingest trigger
  - Files: `template.yaml`
  - Verify: `aws s3api get-bucket-notification-configuration`

- [ ] **T5 (P1, human: ~1h / CC: ~15min)** — SAM — Explicit LogGroups for Lite + Discovery (phase 2 prep)
  - Surfaced by: Architecture — missing explicit groups
  - Files: `template.yaml`
  - Verify: Resources present before phase 2 filters

- [ ] **T6 (P2, human: ~2h / CC: ~15min)** — RunReveal — Create staging custom source + field mapping
  - Surfaced by: Architecture — schema mapping
  - Files: RunReveal UI / docs note in `docs/logging-observability.md`
  - Verify: MCP/SQL sample query returns `api_call_logged`

- [ ] **T7 (P2, human: ~2h / CC: ~20min)** — Ops — Firehose delivery failure CloudWatch alarm
  - Surfaced by: Failure modes — silent pipeline break
  - Files: `template.yaml`
  - Verify: Alarm exists in staging console

- [ ] **T8 (P2, human: ~3h / CC: ~25min)** — Docs — Update `logging-observability.md` investigation flow (step 6: RunReveal app logs)
  - Surfaced by: What already exists — correlation
  - Files: `docs/logging-observability.md`
  - Verify: Peer can follow doc

- [ ] **T9 (P3, human: ~2h / CC: ~20min)** — Phase 2 — Remaining log group subscriptions
  - Surfaced by: Rollout D1-B phase 2
  - Files: `template.yaml`
  - Verify: All explicit LogGroups subscribed

- [ ] **T10 (P3, human: ~4h / CC: ~30min)** — Detections — Starter rules (`payment_settlement_failed`, spike in `storage_delete_internal_error`, etc.)
  - Surfaced by: Product goal
  - Files: RunReveal console
  - Verify: Test event triggers alert in staging

---

## Worktree parallelization

| Step | Modules touched | Depends on |
|------|-----------------|------------|
| T1 Bucket + policy | `template.yaml` | — |
| T2 Firehose + IAM | `template.yaml` | T1 |
| T3 Subscriptions | `template.yaml` | T2, LogGroups |
| T4 S3 notification | `template.yaml` | T1 |
| T5 Lite/Discovery LogGroups | `template.yaml` | — |
| T6 RunReveal UI | external | T4 + traffic |
| T7 Alarms | `template.yaml` | T2 |
| T8 Docs | `docs/` | — |

**Lanes:** Lane A: T1 → T2 → T3 → T4 → T7 (sequential, `template.yaml`). Lane B: T5 + T8 (parallel). Lane C: T6 after staging deploy (external).

**Execution:** Implement Lane A+B in one feature branch; merge to `main` for staging deploy; then T6 verification; then T9–T10 follow-ups.

---

## Suggested detections (after ingest live)

Examples to configure in RunReveal once `event` is indexed:

- `api_call_logged` with `status >= 500` rate spike
- `payment_settlement_failed` / `payment_settlement_error`
- `storage_delete_internal_error`
- `authorizer_debug` denials spike
- API GW `status` 403/401 burst on `/upload` or `/payment`

---

## Completion summary (eng review)

| Item | Result |
|------|--------|
| Step 0: Scope Challenge | Accepted Option A; phased rollout (D1-B) |
| Architecture Review | 6 findings → addressed in plan (schema split, explicit LogGroups, alarms, parameter gate) |
| Code Quality Review | 2 findings → SAM section + DRY RunReveal policy |
| Test Review | Diagram produced, 12 gaps (pre-implementation) |
| Performance Review | 1 finding → cost/bytes review before prod |
| NOT in scope | Written |
| What already exists | Written |
| TODOS.md updates | Proposed below (user to approve at implement time) |
| Failure modes | 1 critical gap (Firehose silent fail) → T7 |
| Outside voice | Skipped (user plan-only session) |
| Parallelization | 2 lanes + external RunReveal |
| Lake Score | N/A (planning) |

---

## Proposed TODOS.md entries (defer until implementation PR)

1. **WAF logs → RunReveal** — Enable WAF logging to S3 and generic source for edge attack visibility.  
2. **CloudWatch backfill export** — One-time export job if historical app logs needed in RunReveal.  
3. **Firehose transform** — Strip Lambda platform lines; normalize API GW + handler JSON to one schema.  
4. **S3 data events on ciphertext buckets** — Deeper audit per `logging-observability.md` note.

---

## Next steps

1. Review this plan; adjust phase 1 group list if needed.  
2. When ready: branch from `main`, implement T1–T4 + T7, PR to staging deploy.  
3. Configure RunReveal staging source (T6); run sample SQL on `api_call_logged`.  
4. Phase 2 PR for remaining log groups; prod promotion via existing workflow.

**No infrastructure changes or deployments have been made as part of this document.**

# Cursor Cloud Agent feature specs (mnemospark)

Small, single-run feature specs for [Cursor Cloud Agents](https://cursor.com/docs/cloud-agent). Each file describes one task completable in one Cloud Agent run.

**Product context:** [mnemospark_PRD.md](../mnemospark_PRD.md), [mnemospark_full_workflow.md](../mnemospark_full_workflow.md), [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md). Larger feature specs live in [.company/features/](../features/).

---

## How to use

1. Pick a feature file below (or from the list in this directory).
2. Start a **Cloud Agent** (Cloud dropdown in the agent input, or [cursor.com/agents](https://cursor.com/agents)).
3. Paste the **task string** from the feature file (or point the agent at the file) so it knows scope and acceptance criteria.
4. The agent works on a **separate branch** and pushes for handoff; verify via "Checkout Branch" or "Open VM" as needed.

---

## Repo mapping (where to run the Cloud Agent)

- **Backend features (01–10, 15–17):** Start the Cloud Agent from the **mnemospark-backend** repo. Seed that repo first by running from mnemospark:  
  `./scripts/seed-mnemospark-backend.sh /path/to/mnemospark-backend`
- **Client features (11–14):** Start the Cloud Agent from the **mnemospark** repo.

The agent must work **only in the repo it was started in**. Do **not** open, clone, or require access to BlockRun/ClawRouter, OpenRouter, or any other repository.

| Features     | Repo to run agent from | Notes                                                                                                                                                                                                                      |
| ------------ | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 01–10, 15–17 | **mnemospark-backend** | Seed first (see above). Backend infra (08, 15–17) is built with **CloudFormation** (or SAM) per [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md).                           |
| 11–14        | **mnemospark**         | Plugin/client.                                                                                                                                                                                                             |

**mnemospark proxy port:** For client features (11–14), the mnemospark proxy listens on **port 7120** by default. Agents and config should use `http://127.0.0.1:7120` when talking to the proxy (configurable via `MNEMOSPARK_PROXY_PORT`).

**AWS documentation (CloudFormation/SAM):** Cloud Agents do not have an AWS MCP server. They have internet access. When implementing backend features (01–10, 15–17), use **[AWS_DOCS_REFERENCES.md](AWS_DOCS_REFERENCES.md)** for official AWS doc URLs (API Gateway, Lambda, DynamoDB, WAF, CloudWatch, CloudFront, SAM). Fetch or open those URLs as needed for resource syntax and properties.

---

## Conventions

Each feature file includes:

- **ID, Repo, Rough size** — one Cloud Agent run.
- **Scope** — what to build in this run only.
- **References** — links to API spec, workflow, design doc, or examples.
- **Cloud Agent** — install (idempotent), start (if needed), secrets, **acceptance criteria (checkboxes)**.
- **Task string (optional)** — copy-paste prompt for the agent.

---

## Ordering / dependencies

- **01, 02, 09** before **03** (price-storage needs estimate Lambdas and DynamoDB).
- **09** before **04** (upload needs transaction log table).
- **08** (API Gateway) can be done after the first Lambda exists; implement via CloudFormation or SAM.
- **15** (WAF), **16** (observability), **17** (CloudFront, optional) after **08**.
- **10** (housekeeping) after **04** (upload).
- **11–14** (client) after backend routes exist.

---

## Feature list

| ID  | File                                                                                     | Description                                       |
| --- | ---------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 01  | [cursor-dev-01-lambda-estimate-storage.md](cursor-dev-01-lambda-estimate-storage.md)     | Lambda POST /estimate/storage                     |
| 02  | [cursor-dev-02-lambda-estimate-transfer.md](cursor-dev-02-lambda-estimate-transfer.md)   | Lambda POST /estimate/transfer                    |
| 03  | [cursor-dev-03-lambda-price-storage.md](cursor-dev-03-lambda-price-storage.md)           | Lambda POST /price-storage                        |
| 04  | [cursor-dev-04-lambda-storage-upload.md](cursor-dev-04-lambda-storage-upload.md)         | Lambda POST /storage/upload                       |
| 05  | [cursor-dev-05-lambda-storage-ls.md](cursor-dev-05-lambda-storage-ls.md)                 | Lambda GET/POST /storage/ls                       |
| 06  | [cursor-dev-06-lambda-storage-download.md](cursor-dev-06-lambda-storage-download.md)     | Lambda GET/POST /storage/download                 |
| 07  | [cursor-dev-07-lambda-storage-delete.md](cursor-dev-07-lambda-storage-delete.md)         | Lambda POST/DELETE /storage/delete                |
| 08  | [cursor-dev-08-api-gateway-auth.md](cursor-dev-08-api-gateway-auth.md)                   | API Gateway + API key + CORS (CloudFormation/SAM) |
| 09  | [cursor-dev-09-dynamodb-tables.md](cursor-dev-09-dynamodb-tables.md)                     | DynamoDB tables (quotes + txn log)                |
| 10  | [cursor-dev-10-housekeeping-32day.md](cursor-dev-10-housekeeping-32day.md)               | Housekeeping job (32-day deadline)                |
| 15  | [cursor-dev-15-cfn-waf.md](cursor-dev-15-cfn-waf.md)                                     | CloudFormation: WAF                               |
| 16  | [cursor-dev-16-cfn-observability.md](cursor-dev-16-cfn-observability.md)                 | CloudFormation: Observability                     |
| 17  | [cursor-dev-17-cfn-cloudfront.md](cursor-dev-17-cfn-cloudfront.md)                       | CloudFormation: CloudFront (optional)             |
| 11  | [cursor-dev-11-client-cloud-backup.md](cursor-dev-11-client-cloud-backup.md)             | Client /cloud backup                              |
| 12  | [cursor-dev-12-client-price-storage.md](cursor-dev-12-client-price-storage.md)           | Client /cloud price-storage                       |
| 13  | [cursor-dev-13-client-upload.md](cursor-dev-13-client-upload.md)                         | Client /cloud upload                              |
| 14  | [cursor-dev-14-client-ls-download-delete.md](cursor-dev-14-client-ls-download-delete.md) | Client /cloud ls, download, delete                |

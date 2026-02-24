# Object storage management REST API

Lambda + API Gateway (REST) for wallet-scoped S3 object storage with client-held envelope encryption. Same design pattern as [data-transfer-cost-estimate-api](../data-transfer-cost-estimate-api/) and [s3-cost-estimate-api](../s3-cost-estimate-api/).

**Commands:** `upload`, `ls`, `list`, `download`, `delete`. KEK is stored in **AWS Secrets Manager** per wallet (`mnemospark/wallet/<wallet_hash>`); the Lambda creates the secret on first upload if missing.

## Prerequisites

- AWS CLI configured (e.g. `aws configure`)
- **AWS SAM CLI** (provides the `sam` command):
  - **macOS (Homebrew):** `brew install aws-sam-cli`
  - **Other / official installers:** [Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
  - Verify: `sam --version`
- **Python 3.13** (or match `Runtime` in `template.yaml`) so `sam build` finds a matching interpreter.

## Deploy

From this directory (`examples/object-storage-management-api/`):

```bash
sam build
sam deploy --guided
```

On first deploy, set **Stack name** (e.g. `object-storage-management`) and **AWS Region**. Subsequent deploys:

```bash
sam build && sam deploy
```

## Invoke the API

After deploy, use the API URL from stack **Outputs**. Send the API key in the **`x-api-key`** header. All requests are **POST** to `/storage` with a JSON body.

**Body fields:**

| Field            | Required                      | Description                                              |
| ---------------- | ----------------------------- | -------------------------------------------------------- |
| `command`        | Yes                           | `upload` \| `ls` \| `list` \| `download` \| `delete`     |
| `wallet_address` | Yes                           | Wallet address (used to derive bucket and KEK secret id) |
| `location`       | No                            | AWS region (default `us-east-1`)                         |
| `object_key`     | For upload/ls/download/delete | S3 object key (single path segment, no `/`)              |
| `content`        | For upload only               | Base64-encoded file content                              |

**List bucket (all keys):**

```bash
curl -X POST "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/storage" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "list", "wallet_address": "0xYourWalletAddress", "location": "us-east-1"}'
```

**Ls (single object metadata):**

```bash
curl -X POST "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/storage" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "wallet_address": "0xYourWalletAddress", "object_key": "myfile.txt", "location": "us-east-1"}'
```

**Upload (content as base64):**

```bash
# Encode file first (Linux: base64 -w0 myfile.txt; macOS: base64 -i myfile.txt | tr -d '\n')
CONTENT=$(base64 -w0 myfile.txt 2>/dev/null || base64 -i myfile.txt | tr -d '\n')
curl -X POST "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/storage" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"upload\", \"wallet_address\": \"0xYourWalletAddress\", \"object_key\": \"myfile.txt\", \"location\": \"us-east-1\", \"content\": \"$CONTENT\"}"
```

**Download (returns base64 content in JSON):**

```bash
curl -X POST "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/storage" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "download", "wallet_address": "0xYourWalletAddress", "object_key": "myfile.txt", "location": "us-east-1"}'
```

**Delete:**

```bash
curl -X POST "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/storage" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "delete", "wallet_address": "0xYourWalletAddress", "object_key": "myfile.txt", "location": "us-east-1"}'
```

## Get the API URL after deploy

```bash
aws cloudformation describe-stacks --stack-name object-storage-management --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text
```

(Use your stack name and add `--region REGION` if needed.)

## API key

The template requires an API key. SAM creates a usage plan and one key when you deploy. Get the key value from [API Gateway → API keys](https://console.aws.amazon.com/apigateway/home#/api-keys) (same region as the stack) — open the key named like `ObjectStorageManagementApiApiKey` and click **Show** to copy the value. Send it in the **`x-api-key`** header on every request.

To turn off the API key, remove the `Auth:` block from the `ObjectStorageManagementApi` resource in `template.yaml` and redeploy.

## Encryption and Secrets Manager

- Bucket name: `mnemospark-<wallet_hash>` (16-char hex hash of wallet address).
- KEK (32 bytes) is stored in Secrets Manager as secret id `mnemospark/wallet/<wallet_hash>`. The Lambda creates it on first upload for that wallet.
- Each object is encrypted with a unique DEK; the DEK is wrapped with the KEK and stored in S3 object metadata (`wrapped-dek`). The CLI script uses a local KEK under `~/.openclaw/mnemospark/keys/`; the API uses Secrets Manager so the same wallet can be used from Lambda without local key files.

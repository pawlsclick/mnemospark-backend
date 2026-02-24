# S3 storage cost estimate REST API

Lambda + API Gateway (REST) so you can call the S3 cost estimate as an HTTP endpoint.

## Prerequisites

- AWS CLI configured (e.g. `aws configure`)
- **AWS SAM CLI** (provides the `sam` command):
  - **macOS (Homebrew):** `brew install aws-sam-cli`
  - **Other / official installers:** [Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
  - Verify: `sam --version`
- **Python 3.13** (or match `Runtime` in `template.yaml`) so `sam build` finds a matching interpreter. SAM validates your local Python against the Lambda runtime; if build fails, change `Runtime` in `template.yaml` to your version (e.g. `python3.11` or `python3.12`) or install that version and put it on your PATH.

## Deploy

From this directory (`examples/s3-cost-estimate-api/`):

```bash
# Build (packages Lambda code)
sam build

# Deploy (creates/updates CloudFormation stack; requires confirmation for IAM)
sam deploy --guided
```

On first deploy, `--guided` will prompt for:

- **Stack name**: e.g. `s3-cost-estimate-api`
- **AWS Region**: e.g. `us-east-1` (BCM Pricing Calculator is in us-east-1)
- **Confirm changes before deploy**: Y
- **Allow SAM CLI IAM role creation**: Y
- **Disable rollback**: N
- **Save arguments to samconfig.toml**: Y (so next time you can run `sam deploy` without `--guided`)

Subsequent deploys (also use this to **update** the stack after code changes, e.g. to support `region` in the API):

```bash
cd examples/s3-cost-estimate-api
sam build && sam deploy
```

Use the same stack name and region as first deploy (e.g. `mnemospark-cost-estimate` in `eu-north-1`); answer prompts or rely on `samconfig.toml` if you saved args.

## Invoke the API

After deploy, the stack **Outputs** give the API URL. Use it like this:

**GET (query params):**

```bash
# Required: gb. Optional: region, rate_type (BEFORE_DISCOUNTS | AFTER_DISCOUNTS | AFTER_DISCOUNTS_AND_COMMITMENTS)
curl -H "x-api-key: YOUR_KEY" "https://YOUR_API_ID.execute-api.eu-north-1.amazonaws.com/prod/estimate?gb=100"
curl -H "x-api-key: YOUR_KEY" "https://YOUR_API_ID.execute-api.eu-north-1.amazonaws.com/prod/estimate?gb=100&region=eu-north-1"
```

**POST (JSON body):**

```bash
curl -X POST "https://YOUR_API_ID.execute-api.eu-north-1.amazonaws.com/prod/estimate" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"gb": 100, "region": "eu-north-1", "rateType": "BEFORE_DISCOUNTS"}'
```

**Example response (200):**

```json
{
  "estimatedCost": 2.3,
  "currency": "USD",
  "storageGbMonth": 100,
  "region": "us-east-1",
  "rateType": "BEFORE_DISCOUNTS"
}
```

## Get the API URL after deploy

```bash
aws cloudformation describe-stacks --stack-name s3-cost-estimate-api --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text
```

Or open the stack in the AWS Console → **Outputs** tab.

## API key (included)

The template requires an **API key** for all requests. SAM creates a usage plan and one API key when you deploy.

### Get the API key value after deploy

The key is created by CloudFormation but the **value** is not in the stack outputs (for security). Use one of these:

**Option A – API Gateway console**

1. Open [API Gateway → API keys](https://console.aws.amazon.com/apigateway/home#/api-keys) (same region as the stack).
2. Open the key named like `S3CostEstimateApiApiKey` (or the name shown for your stack).
3. Click **Show** next to **API key** and copy the value.

**Option B – AWS CLI**

```bash
# List API key IDs for the account
aws apigateway get-api-keys --include-values --query "items[?name=='S3CostEstimateApiApiKey'].value" --output text

# If you have the key ID (from list without --include-values, or from console)
aws apigateway get-api-key --api-key YOUR_KEY_ID --include-value --query "value" --output text
```

Use the **region** where you deployed (e.g. `--region us-east-1`).

### Call the API with the key

Send the key in the **`x-api-key`** header:

```bash
curl -H "x-api-key: YOUR_API_KEY" "https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/estimate?gb=100"
```

Without a valid key, API Gateway returns `403 Forbidden`.

### Optional: turn off API key

To make the API public again, remove the `Auth:` block (and the `X-Api-Key` CORS header if you added it) from the `S3CostEstimateApi` resource in `template.yaml`, then redeploy.

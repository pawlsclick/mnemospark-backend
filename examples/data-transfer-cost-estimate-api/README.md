# Data transfer cost estimate REST API

Lambda + API Gateway (REST) so you can call the data transfer cost estimate as an HTTP endpoint. Same design pattern as [s3-cost-estimate-api](../s3-cost-estimate-api/).

## Prerequisites

- AWS CLI configured (e.g. `aws configure`)
- **AWS SAM CLI** (provides the `sam` command):
  - **macOS (Homebrew):** `brew install aws-sam-cli`
  - **Other / official installers:** [Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
  - Verify: `sam --version`
- **Python 3.13** (or match `Runtime` in `template.yaml`) so `sam build` finds a matching interpreter.

## Deploy

From this directory (`examples/data-transfer-cost-estimate-api/`):

```bash
sam build
sam deploy --guided
```

On first deploy, set **Stack name** (e.g. `data-transfer-cost-estimate`) and **AWS Region**. Subsequent deploys:

```bash
sam build && sam deploy
```

## Invoke the API

After deploy, use the API URL from stack **Outputs**. Send the API key in the **`x-api-key`** header.

**GET (query params):**

```bash
# direction: in (ingress/regional) or out (egress). Optional: gb, region, rate_type
curl -H "x-api-key: YOUR_KEY" "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/estimate?direction=in&gb=100"
curl -H "x-api-key: YOUR_KEY" "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/estimate?direction=out&gb=500&region=eu-north-1"
```

**POST (JSON body):**

```bash
curl -X POST "https://YOUR_API_ID.execute-api.REGION.amazonaws.com/prod/estimate" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"direction": "in", "gb": 100, "region": "us-east-1", "rateType": "BEFORE_DISCOUNTS"}'
```

**Example response (200):**

```json
{
  "estimatedCost": 1.0,
  "currency": "USD",
  "dataGb": 100,
  "direction": "in",
  "region": "us-east-1",
  "rateType": "BEFORE_DISCOUNTS"
}
```

## Get the API URL after deploy

```bash
aws cloudformation describe-stacks --stack-name data-transfer-cost-estimate --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text
```

(Use your stack name and add `--region REGION` if needed.)

## API key

The template requires an API key. SAM creates a usage plan and one key when you deploy. Get the key value from [API Gateway → API keys](https://console.aws.amazon.com/apigateway/home#/api-keys) (same region as the stack) — open the key named like `DataTransferCostEstimateApiApiKey` and click **Show** to copy the value. Send it in the **`x-api-key`** header on every request.

To turn off the API key, remove the `Auth:` block from the `DataTransferCostEstimateApi` resource in `template.yaml` and redeploy.

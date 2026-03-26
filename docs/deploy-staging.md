# Deploying mnemospark-backend to staging

Routine deploys use **GitHub Actions** on push to `main` (see `.github/workflows/deploy-staging.yml`). The workflow assumes an AWS account with OIDC and the **staging** GitHub environment configured.

## IAM role (OIDC)

The workflow assumes an IAM role via `aws-actions/configure-aws-credentials` using `secrets.AWS_ROLE_ARN_STAGING`. For emergency or debug deploys from a workstation, you can use a dedicated deploy role (example used in ops docs): `arn:aws:iam::REDACTED:role/STAGING_DEPLOY_ROLE`. Prefer short-lived credentials and least privilege; do not commit long-lived access keys.

## Stack and region

Staging stack name is **`mnemospark-staging`** (see `samconfig.staging.toml`). Region is set by the GitHub variable `AWS_REGION` (for example `us-east-1`).

## Dashboard GraphQL API key (required)

The dashboard GraphQL HTTP API (`POST /graphql`) is protected by a **Lambda request authorizer** that validates the **`x-api-key`** header against **AWS Secrets Manager** (`template.yaml` parameter `DashboardGraphqlApiKeySecretArn`).

1. Create a secret in Secrets Manager (plaintext string or JSON with `api_key` / `apiKey`) in the same account and region as the stack.
2. Set the GitHub repository or environment variable **`DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN`** to that secret’s ARN.
3. The deploy workflow passes `DashboardGraphqlApiKeySecretArn` into `sam deploy` via `--parameter-overrides` together with existing staging parameters.

Until this variable is set to a valid ARN, CloudFormation deploys that include the dashboard GraphQL authorizer will fail or the authorizer will deny traffic if the secret cannot be read.

## Local `sam deploy` (emergency)

`samconfig.staging.toml` includes `DashboardGraphqlApiKeySecretArn=REPLACE_WITH_SECRET_ARN`; replace that placeholder (or pass `--parameter-overrides` on the command line).

```bash
sam build --template-file template.yaml
sam deploy --config-file samconfig.staging.toml --region "$AWS_REGION" \
  --parameter-overrides \
    "StageName=staging PaymentSettlementMode=onchain BaseRpcUrl=https://mainnet.base.org DashboardGraphqlApiKeySecretArn=YOUR_SECRET_ARN"
```

Replace `YOUR_SECRET_ARN` with the real ARN. Ensure your credentials can assume the deploy role or equivalent and can update the stack.

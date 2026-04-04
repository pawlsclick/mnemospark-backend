# Deploying mnemospark-backend to staging

Routine deploys use **GitHub Actions** on push to `main` (see `.github/workflows/deploy-staging.yml`). The workflow assumes an AWS account with OIDC and the **staging** GitHub environment configured.

## IAM role (OIDC)

The workflow assumes an IAM role via `aws-actions/configure-aws-credentials` using `secrets.AWS_ROLE_ARN_STAGING`. For emergency or debug deploys from a workstation, use a dedicated deploy role documented in your ops runbook (`arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>`); do not commit account-specific ARNs in this repository. Prefer short-lived credentials and least privilege; do not commit long-lived access keys.

## Stack and region

Staging stack name is **`mnemospark-staging`** (see `samconfig.staging.toml`). Region is set by the GitHub variable `AWS_REGION` (for example `us-east-1`).

## Required GitHub Variables (staging environment)

The **Deploy Staging** job fails with a clear error if any of the following are missing (except `BASE_RPC_URL` when `PAYMENT_SETTLEMENT_MODE` is `mock`).

| GitHub variable | SAM / CloudFormation parameter | Notes |
|-----------------|--------------------------------|-------|
| `DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN` | `DashboardGraphqlApiKeySecretArn` | Secrets Manager **ARN** for dashboard GraphQL `x-api-key` (see below). |
| `PAYMENT_SETTLEMENT_MODE` | `PaymentSettlementMode` | `mock` or `onchain` (must be set explicitly). |
| `BASE_RPC_URL` | `BaseRpcUrl` | Base JSON-RPC URL; **required when** `PAYMENT_SETTLEMENT_MODE=onchain`. May be empty for `mock`. |
| `MNEMOSPARK_RECIPIENT_WALLET` | `MnemosparkRecipientWallet` | `0x…` recipient for x402 USDC payments. |
| `RELAYER_WALLET_ADDRESS` | `RelayerWalletAddress` | `0x…` relayer public address (must match key in Secrets Manager). |
| `PAYMENT_ASSET_ADDRESS` | `PaymentAssetAddress` | Token contract `0x…` (e.g. USDC on Base). |
| `RELAYER_PRIVATE_KEY_SECRET_ID` | `RelayerPrivateKeySecretId` | Secrets Manager secret **name/id** (not ARN) holding the relayer private key; passed to `MNEMOSPARK_RELAYER_SECRET_ID`. Operators create this secret in AWS; do not commit key material. |

Optional (defaults shown if unset in the workflow):

| GitHub variable | SAM parameter | Default in workflow |
|-----------------|---------------|---------------------|
| `PRICE_STORAGE_FLOOR` | `PriceStorageFloor` | `0` |
| `PRICE_STORAGE_MARKUP` | `PriceStorageMarkup` | `0` |

`PaymentNetwork` and other template parameters keep their `template.yaml` defaults unless you add overrides locally.

## Dashboard GraphQL API key (required)

The dashboard GraphQL HTTP API (`POST /graphql`) is protected by a **Lambda request authorizer** that validates the **`x-api-key`** header against **AWS Secrets Manager** (`template.yaml` parameter `DashboardGraphqlApiKeySecretArn`).

1. Create a secret in Secrets Manager (plaintext string or JSON with `api_key`, `apiKey`, or `api_key_dashboard`) in the same account and region as the stack.
2. Set **`DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN`** to that secret’s ARN.
3. The deploy workflow passes it into `sam deploy` via `--parameter-overrides` with the other required parameters.

Until this variable is set to a valid ARN, CloudFormation deploys that include the dashboard GraphQL authorizer will fail or the authorizer will deny traffic if the secret cannot be read.

## Relayer private key (Secrets Manager)

Create a **per-environment** secret in Secrets Manager containing the relayer private key (format your runtime expects, e.g. hex). Set **`RELAYER_PRIVATE_KEY_SECRET_ID`** to that secret’s **name** (same string you would pass to `GetSecretValue` as `SecretId`). The stack IAM policy allows `GetSecretValue` only for `arn:…:secret:<that-name>*` (suffix matches AWS’s random suffix). Use distinct secret names for staging vs production when both stacks live in one account.

## Price-storage quote settings (optional)

The **`staging`** environment can define **`PRICE_STORAGE_FLOOR`** and **`PRICE_STORAGE_MARKUP`**. The deploy workflow passes them to SAM as **`PriceStorageFloor`** and **`PriceStorageMarkup`**. If you omit them, both default to `0` on deploy. See [price-storage.md](price-storage.md) for semantics. Redeploy after changing these values so the stack updates the Lambda configuration.

## Local `sam deploy` (emergency)

`samconfig.staging.toml` uses **`REPLACE_*` placeholders** for payment and RPC parameters. Replace every placeholder (or pass `--parameter-overrides` on the command line and rely on CLI overrides).

```bash
sam build --template-file template.yaml
sam deploy --config-file samconfig.staging.toml --region "$AWS_REGION" \
  --parameter-overrides \
    "StageName=staging" \
    "PaymentSettlementMode=onchain" \
    "BaseRpcUrl=https://mainnet.base.org" \
    "DashboardGraphqlApiKeySecretArn=YOUR_SECRET_ARN" \
    "MnemosparkRecipientWallet=0x…" \
    "RelayerWalletAddress=0x…" \
    "PaymentAssetAddress=0x…" \
    "RelayerPrivateKeySecretId=your/secret-name" \
    "PriceStorageFloor=0" \
    "PriceStorageMarkup=0"
```

Replace placeholders with real values. Ensure your credentials can assume the deploy role or equivalent and can update the stack.

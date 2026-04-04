# Deploying mnemospark-backend to staging

Routine deploys use **GitHub Actions** on push to `main` (see `.github/workflows/deploy-staging.yml`). The workflow assumes an AWS account with OIDC and the **staging** GitHub environment configured.

## IAM role (OIDC)

The workflow assumes an IAM role via `aws-actions/configure-aws-credentials` using `secrets.AWS_ROLE_ARN_STAGING`. For emergency or debug deploys from a workstation, use a dedicated deploy role documented in your ops runbook (`arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>`); do not commit account-specific ARNs in this repository. Prefer short-lived credentials and least privilege; do not commit long-lived access keys.

## Stack and region

Staging stack name is **`mnemospark-staging`** (see `samconfig.staging.toml`). Region is set by the GitHub variable `AWS_REGION` (for example `us-east-1`).

## Secrets Manager (dashboard GraphQL key and relayer private key)

**Do not store API key or private key material in GitHub.** Those values live only in **AWS Secrets Manager** in the same account and region as the stack.

The stack resolves secret **names** from `StageName` and the `MnemosparkSecretsPathPrefix` parameter (default **`mnemospark`**):

| Purpose | Secret name (staging `StageName=staging`) |
|---------|---------------------------------------------|
| Dashboard GraphQL `x-api-key` | `mnemospark/staging/dashboard-graphql-api-key` |
| Relayer private key (`POST /payment/settle` on-chain) | `mnemospark/staging/relayer-private-key` |

For production (`StageName=prod`), the same pattern uses **`mnemospark/prod/...`**. Create distinct secrets per environment; IAM `GetSecretValue` is scoped to those paths.

**Before the first deploy** (or after renaming secrets), create each secret in Secrets Manager with the expected name. Plaintext or JSON (see dashboard authorizer code for accepted JSON keys) is supported for the dashboard key.

To use a non-default prefix (rare), pass `MnemosparkSecretsPathPrefix=...` in `sam deploy --parameter-overrides` (not required for GitHub Actions unless you add it to the workflow).

## Required GitHub Variables (staging environment)

The **Deploy Staging** job fails with a clear error if any of the following are missing (except `BASE_RPC_URL` when `PAYMENT_SETTLEMENT_MODE` is `mock`).

| GitHub variable | SAM / CloudFormation parameter | Notes |
|-----------------|--------------------------------|-------|
| `PAYMENT_SETTLEMENT_MODE` | `PaymentSettlementMode` | `mock` or `onchain` (must be set explicitly). |
| `BASE_RPC_URL` | `BaseRpcUrl` | Base JSON-RPC URL; **required when** `PAYMENT_SETTLEMENT_MODE=onchain`. May be empty for `mock`. |
| `MNEMOSPARK_RECIPIENT_WALLET` | `MnemosparkRecipientWallet` | `0x…` recipient for x402 USDC payments. |
| `RELAYER_WALLET_ADDRESS` | `RelayerWalletAddress` | `0x…` relayer public address (must match the key in `mnemospark/staging/relayer-private-key`). |
| `PAYMENT_ASSET_ADDRESS` | `PaymentAssetAddress` | Token contract `0x…` (e.g. USDC on Base). |

Optional (defaults shown if unset in the workflow):

| GitHub variable | SAM parameter | Default in workflow |
|-----------------|---------------|---------------------|
| `PRICE_STORAGE_FLOOR` | `PriceStorageFloor` | `0` |
| `PRICE_STORAGE_MARKUP` | `PriceStorageMarkup` | `0` |

`PaymentNetwork` and other template parameters keep their `template.yaml` defaults unless you add overrides locally.

## Dashboard GraphQL API key (Secrets Manager only)

The dashboard GraphQL HTTP API (`POST /graphql`) authorizer reads the expected `x-api-key` from **`mnemospark/<stage>/dashboard-graphql-api-key`** (see table above). No GitHub variable or secret is used for that identifier or value.

## Price-storage quote settings (optional)

The **`staging`** environment can define **`PRICE_STORAGE_FLOOR`** and **`PRICE_STORAGE_MARKUP`**. The deploy workflow passes them to SAM as **`PriceStorageFloor`** and **`PriceStorageMarkup`**. If you omit them, both default to `0` on deploy. See [price-storage.md](price-storage.md) for semantics. Redeploy after changing these values so the stack updates the Lambda configuration.

## Local `sam deploy` (emergency)

`samconfig.staging.toml` uses **`REPLACE_*` placeholders** for payment and RPC parameters. Replace every placeholder (or pass `--parameter-overrides` on the command line).

Ensure Secrets Manager already has **`mnemospark/staging/dashboard-graphql-api-key`** and **`mnemospark/staging/relayer-private-key`** (or your chosen `MnemosparkSecretsPathPrefix` + `StageName`) before deploy.

```bash
sam build --template-file template.yaml
sam deploy --config-file samconfig.staging.toml --region "$AWS_REGION" \
  --parameter-overrides \
    "StageName=staging" \
    "PaymentSettlementMode=onchain" \
    "BaseRpcUrl=https://mainnet.base.org" \
    "MnemosparkRecipientWallet=0x…" \
    "RelayerWalletAddress=0x…" \
    "PaymentAssetAddress=0x…" \
    "PriceStorageFloor=0" \
    "PriceStorageMarkup=0"
```

Replace placeholders with real values. Ensure your credentials can assume the deploy role or equivalent and can update the stack.

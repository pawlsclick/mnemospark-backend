# Deployment Runbook (Stage -> Prod)

## Prerequisites
- GitHub Environments:
  - `staging` (auto)
  - `production` (required reviewers)
- GitHub secrets:
  - `AWS_ROLE_ARN_STAGING`
  - `AWS_ROLE_ARN_PROD`
- GitHub variables (repository or environment-scoped as noted in [deploy-staging.md](deploy-staging.md)):
  - `AWS_REGION`
  - `STAGING_BASE_URL` (staging)
  - `PROD_BASE_URL` (production)
  - `ZAP_TARGET_URL_STAGING`
  - **Staging** (`staging` environment) and **production** (`production` environment) must each define:
    - `DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN`
    - `PAYMENT_SETTLEMENT_MODE` (`mock` or `onchain`)
    - `BASE_RPC_URL` (required when `PAYMENT_SETTLEMENT_MODE=onchain`)
    - `MNEMOSPARK_RECIPIENT_WALLET`
    - `RELAYER_WALLET_ADDRESS`
    - `PAYMENT_ASSET_ADDRESS`
    - `RELAYER_PRIVATE_KEY_SECRET_ID` (Secrets Manager secret **name** for relayer private key; operators create the secret in AWS, never commit key material)
  - Optional in both environments: `PRICE_STORAGE_FLOOR`, `PRICE_STORAGE_MARKUP` (default `0` in workflows if unset)

See [deploy-staging.md](deploy-staging.md) for column semantics and operator notes (GraphQL API key ARN vs relayer secret **id**).

## First-time bootstrap
```bash
sam build
sam deploy --guided --config-file samconfig.staging.toml
sam deploy --guided --config-file samconfig.prod.toml
```

After this change, guided deploy must supply **`PaymentSettlementMode`**, **`BaseRpcUrl`**, **`RelayerPrivateKeySecretId`**, and wallet/asset addresses explicitly (or use `samconfig.*.toml` placeholders replaced before deploy).

## Standard flow
1. Merge PR to `main`
2. `Deploy Staging` runs automatically (ensure staging GitHub variables are set **before** merge, or the job will fail until they are)
3. `Security Post Deploy` runs (Trivy, Checkov, ZAP)
4. Trigger `Promote to Production` manually
5. Production deploy requires environment approval

## Rollback
Use CloudFormation stack history to redeploy previous known-good template/artifact and re-run smoke tests.

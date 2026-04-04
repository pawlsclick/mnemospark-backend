# Deployment Runbook (Stage -> Prod)

## Prerequisites
- GitHub Environments:
  - `staging` (auto)
  - `production` (required reviewers)
- GitHub secrets:
  - `AWS_ROLE_ARN_STAGING`
  - `AWS_ROLE_ARN_PROD`
- GitHub variables (repository or environment-scoped as noted in [deploy-staging.md](deploy-staging.md)):
  - `AWS_REGION` — must be visible to each deploy job. **Environment-scoped** variables apply only to that environment: if `AWS_REGION` is set only on **staging**, **Promote to Production** still fails until you set `AWS_REGION` on **production** as well, **or** define `AWS_REGION` once as a **repository** Actions variable (recommended if staging and prod use the same region).
  - `STAGING_BASE_URL` (staging)
  - `PROD_BASE_URL` (production)
  - `ZAP_TARGET_URL_STAGING`
  - **Staging** (`staging` environment) and **production** (`production` environment) must each define:
    - `PAYMENT_SETTLEMENT_MODE` (`mock` or `onchain`)
    - `BASE_RPC_URL` (required when `PAYMENT_SETTLEMENT_MODE=onchain`)
    - `MNEMOSPARK_RECIPIENT_WALLET`
    - `RELAYER_WALLET_ADDRESS`
    - `PAYMENT_ASSET_ADDRESS`
  - Optional in both environments: `PRICE_STORAGE_FLOOR`, `PRICE_STORAGE_MARKUP` (default `0` in workflows if unset)

**Dashboard GraphQL API key and relayer private key** are **not** configured in GitHub. Create them in **AWS Secrets Manager** at **`mnemospark/<stage>/dashboard-graphql-api-key`** and **`mnemospark/<stage>/relayer-private-key`** where `<stage>` matches **`StageName`** (`staging` or `prod`). See [deploy-staging.md](deploy-staging.md).

## First-time bootstrap
```bash
sam build
sam deploy --guided --config-file samconfig.staging.toml
sam deploy --guided --config-file samconfig.prod.toml
```

Guided deploy must supply **`PaymentSettlementMode`**, **`BaseRpcUrl`**, and wallet/asset addresses explicitly (or use `samconfig.*.toml` placeholders replaced before deploy). Ensure Secrets Manager secrets exist at the paths described in [deploy-staging.md](deploy-staging.md).

## Standard flow
1. Merge PR to `main`
2. `Deploy Staging` runs automatically (ensure staging GitHub variables are set **before** merge, or the job will fail until they are)
3. `Security Post Deploy` runs (Trivy, Checkov, ZAP)
4. Trigger `Promote to Production` manually
5. Production deploy requires environment approval

## Rollback
Use CloudFormation stack history to redeploy previous known-good template/artifact and re-run smoke tests.

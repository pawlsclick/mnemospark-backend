# Deployment Runbook (Stage -> Prod)

## Prerequisites
- GitHub Environments:
  - `staging` (auto)
  - `production` (required reviewers)
- GitHub secrets:
  - `AWS_ROLE_ARN_STAGING`
  - `AWS_ROLE_ARN_PROD`
- GitHub vars:
  - `AWS_REGION`
  - `STAGING_BASE_URL`
  - `PROD_BASE_URL`
  - `ZAP_TARGET_URL_STAGING`

## First-time bootstrap
```bash
sam build
sam deploy --guided --config-file samconfig.staging.toml
sam deploy --guided --config-file samconfig.prod.toml
```

## Standard flow
1. Merge PR to `main`
2. `Deploy Staging` runs automatically
3. `Security Post Deploy` runs (Trivy, Checkov, ZAP)
4. Trigger `Promote to Production` manually
5. Production deploy requires environment approval

## Rollback
Use CloudFormation stack history to redeploy previous known-good template/artifact and re-run smoke tests.

# WAF stack for API Gateway stage

This stack adds AWS WAF protection for the existing mnemospark REST API stage from cursor-dev-08.

## What it creates

- `AWS::WAFv2::WebACL` (scope `REGIONAL`)
- AWS managed rule groups:
  - `AWSManagedRulesCommonRuleSet`
  - `AWSManagedRulesKnownBadInputsRuleSet`
- Custom rate-based rule:
  - `PriceStoragePerIpRateLimit` (per-IP limit for `/price-storage`)
- `AWS::WAFv2::WebACLAssociation` to an existing API Gateway REST API stage

## Validate

```bash
aws cloudformation validate-template \
  --template-body file://infrastructure/waf/template.yaml
```

## Deploy after API stack

1. Get the existing API ID from the API stack (`MnemosparkBackendApi` logical resource):

```bash
API_ID="$(aws cloudformation describe-stack-resource \
  --stack-name <api-stack-name> \
  --logical-resource-id MnemosparkBackendApi \
  --query 'StackResourceDetail.PhysicalResourceId' \
  --output text)"
```

2. Create a reviewable change set (dry run) for the WAF stack:

```bash
aws cloudformation deploy \
  --template-file infrastructure/waf/template.yaml \
  --stack-name <waf-stack-name> \
  --parameter-overrides ApiGatewayRestApiId="${API_ID}" ApiGatewayStageName=prod PriceStorageRateLimitPer5Min=300 \
  --tags Project=mnemospark \
  --no-execute-changeset
```

3. Deploy for real (remove dry-run flag):

```bash
aws cloudformation deploy \
  --template-file infrastructure/waf/template.yaml \
  --stack-name <waf-stack-name> \
  --parameter-overrides ApiGatewayRestApiId="${API_ID}" ApiGatewayStageName=prod PriceStorageRateLimitPer5Min=300 \
  --tags Project=mnemospark
```

## Parameters

- `ApiGatewayRestApiId` (required): REST API ID from the API stack.
- `ApiGatewayStageName` (default: `prod`): stage to protect.
- `WebAclName` (default: `mnemospark-api-web-acl`): Web ACL name.
- `PriceStorageRateLimitPer5Min` (default: `300`): max requests per 5-minute window per source IP for `/price-storage`.

## Notes on per-wallet rate limiting

WAF can rate-limit by IP and request attributes (for example headers), but it cannot directly consume API Gateway Lambda authorizer context. Because `walletAddress` is provided by the authorizer context (not a first-class WAF key), per-wallet throttling for `POST /price-storage` should be enforced in Lambda/business logic.

# CloudFront stack in front of API Gateway

This optional stack adds an Amazon CloudFront distribution in front of the existing mnemospark API Gateway deployment from cursor-dev-08.

## What it creates

- `AWS::CloudFront::Distribution` with origin = API Gateway domain
- HTTPS-only viewer protocol policy
- Origin protocol policy set to HTTPS-only with origin TLS `TLSv1.2`
- Optional custom domain aliases + ACM certificate
- Optional edge Web ACL attachment (`WafWebAclArn`)

All taggable resources created by this template are tagged with `Project=mnemospark`.

## Parameters

- `ApiGatewayOriginDomainName` (required): API Gateway domain without scheme/path, for example:
  - `abc123.execute-api.<region>.amazonaws.com` (invoke URL domain)
  - `api.example.com` (API Gateway custom domain)
- `ApiGatewayOriginPath` (default: `/prod`): origin path, usually the API stage path; set to empty for a base-path-mapped custom domain.
- `AlternateDomainNames` (optional): CloudFront alias names, comma-delimited.
- `CloudFrontAcmCertificateArn` (optional): ACM certificate ARN for aliases (must use CloudFront's certificate region).
- `WafWebAclArn` (optional): CloudFront-scope WAFv2 Web ACL ARN.

## Validate

```bash
source /workspace/.venv/bin/activate
aws cloudformation validate-template \
  --template-body file://infrastructure/cloudfront/template.yaml
```

## Deploy (change set first)

```bash
aws cloudformation deploy \
  --template-file infrastructure/cloudfront/template.yaml \
  --stack-name <cloudfront-stack-name> \
  --parameter-overrides \
    ApiGatewayOriginDomainName=<api-id>.execute-api.<region>.amazonaws.com \
    ApiGatewayOriginPath=/prod \
  --tags Project=mnemospark \
  --no-execute-changeset
```

Deploy for real by removing `--no-execute-changeset`.

## Deploy with custom domain + ACM

```bash
aws cloudformation deploy \
  --template-file infrastructure/cloudfront/template.yaml \
  --stack-name <cloudfront-stack-name> \
  --parameter-overrides \
    ApiGatewayOriginDomainName=<api-id>.execute-api.<region>.amazonaws.com \
    ApiGatewayOriginPath=/prod \
    AlternateDomainNames=api.example.com \
    CloudFrontAcmCertificateArn=arn:aws:acm:<cloudfront-certificate-region>:<account-id>:certificate/<certificate-id> \
  --tags Project=mnemospark \
  --no-execute-changeset
```

## DNS for alternate domain (example)

If you use `AlternateDomainNames`, create a DNS alias/CNAME to the output `CloudFrontDomainName`.

- Route 53 alias target hosted zone ID for CloudFront: `Z2FDTNDATAQYW2`
- Record target: output `CloudFrontDomainName` (for example, `d111111abcdef8.cloudfront.net`)

## TLS note

When aliases + ACM are provided, the template sets:

- `ViewerProtocolPolicy: https-only`
- `MinimumProtocolVersion: TLSv1.2_2021`

If aliases are not provided, CloudFront uses the default certificate (`*.cloudfront.net`).

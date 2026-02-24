# AWS documentation references for Cursor Cloud Agents

Cloud Agents **do not** have access to an AWS knowledge MCP server. They **do** have **internet access**. Use this page to look up official AWS documentation when implementing CloudFormation or SAM for the cursor-dev features (01–10, 15–17).

## How to use (for the agent)

1. **This repo** already contains design and API specs: [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md), [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md), and the feature files in this directory.
2. **For CloudFormation/SAM resource syntax, properties, and examples**, use the official AWS documentation URLs below. You can fetch a page with `curl -sL "<url>"` and read the relevant sections, or open the URL; prefer the **Developer Guide** and **Resource type** links for accurate YAML/JSON.
3. **Validate templates** with `aws cloudformation validate-template` (CF) or `sam validate` (SAM) before deploying.

---

## By feature (cursor-dev)

| Feature                     | Scope                                                                      | AWS docs to use                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **08** (API Gateway + auth) | REST API, stage, API key, usage plan, CORS, throttling, request validation | [API Gateway REST API protect](https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-protect.html), [Security best practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/security-best-practices.html), [SAM API resource](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html), [CloudFormation AWS::ApiGateway::\*](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_ApiGateway.html)          |
| **09** (DynamoDB)           | Tables, TTL, IAM for Lambdas                                               | [DynamoDB CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_DynamoDB.html), [AWS::DynamoDB::Table](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html), [DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html)                                                                                                                                                                       |
| **15** (WAF)                | Web ACL, managed rule groups, association with API Gateway                 | [WAF for API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html), [AWS::WAFv2::WebACL](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html), [AWS::WAFv2::WebACLAssociation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html), [Managed rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html) |
| **16** (Observability)      | CloudWatch log groups, alarms, API Gateway access logging                  | [API Gateway access logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html), [AWS::Logs::LogGroup](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html), [AWS::CloudWatch::Alarm](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudwatch-alarm.html)                                                                                                                                    |
| **17** (CloudFront)         | Distribution, origin = API Gateway, HTTPS                                  | [CloudFront with API Gateway](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/rest-api-origin.html), [AWS::CloudFront::Distribution](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html)                                                                                                                                                                                                                                     |
| **01–07, 10** (Lambdas)     | Lambda + API events, BCM, S3, DynamoDB                                     | [SAM Function resource](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html), [SAM API events](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-api.html), [AWS Lambda developer guide](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)                                                                                                                                          |

---

## Core reference links (all features)

### Serverless Application Model (SAM)

- [SAM developer guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
- [SAM resource types](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-resources-and-properties.html) — `AWS::Serverless::Api`, `AWS::Serverless::Function`, etc.
- [SAM CLI validate](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-validate.html)

### CloudFormation

- [Validate template](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-validate-template.html): `aws cloudformation validate-template --template-body file://template.yaml`
- [CloudFormation resource types index](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html)

### API Gateway (REST)

- [REST API protect (auth, WAF, throttling)](https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-protect.html)
- [Security best practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/security-best-practices.html)
- [Enable CORS](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html)
- [Request validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html)
- [Usage plans and API keys](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html)

### Lambda

- [Lambda security (public endpoints)](https://docs.aws.amazon.com/lambda/latest/dg/security-public-endpoints.html)
- [Lambda environment and IAM](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)

### DynamoDB

- [DynamoDB table (CloudFormation)](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html)
- [DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html)

### WAF

- [Use AWS WAF to protect REST APIs in API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html)
- [AWS WAF managed rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html)

### Observability

- [API Gateway access logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
- [CloudWatch Alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)

---

## In-repo design (always use first)

- [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md) — Architecture, WAF, API Gateway, CloudFront, observability.
- [mnemospark_backend_api_spec.md](../mnemospark_backend_api_spec.md) — Paths, auth, request/response.
- **examples/s3-cost-estimate-api/template.yaml** — SAM pattern for API + Lambda + API key + CORS (reference for 01, 08).

Use the AWS URLs above when you need exact property names, limits, or syntax for CloudFormation/SAM resources.

---

## Tagging (required)

Tag **every resource that supports tags** with **`Project: mnemospark`** (or `Application: mnemospark`). This includes Lambda functions, API Gateway APIs/stages, DynamoDB tables, WAF Web ACLs, CloudWatch log groups and alarms, CloudFront distributions, and any other taggable resources. In SAM, use the top-level `Tags` property and/or resource-level `Tags` where supported. In CloudFormation, add `Tags` to each resource type that supports them. Ref: [infrastructure_design/internet_facing_API.md](../infrastructure_design/internet_facing_API.md) §9, [Tagging AWS resources](https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html).

# mnemospark-backend

## Observability stack validation and deploy

The root `template.yaml` now includes observability resources for API Gateway and Lambda logs, CloudWatch alarms, and CloudTrail.

### Validate

```bash
source /workspace/.venv/bin/activate
sam validate --template /workspace/template.yaml
aws cloudformation validate-template --template-body file:///workspace/template.yaml
```

### Create a reviewable change set (no execute)

```bash
source /workspace/.venv/bin/activate
sam build --template-file /workspace/template.yaml
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name <stack-name> \
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
  --parameter-overrides StageName=prod \
  --resolve-s3 \
  --no-execute-changeset
```

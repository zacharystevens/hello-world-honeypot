# 🚀 Deployment Guide

## Prerequisites

### Required Tools
- **Terraform** >= 1.0
- **AWS CLI** configured with appropriate credentials
- **Python** 3.9+
- **Git** for version control

### AWS Requirements
- AWS Account with programmatic access
- IAM permissions for Lambda, API Gateway, S3, CloudWatch, SNS
- Preferred region: `us-west-2` (configured in `variables.tf`)

## Quick Deployment

### 1. Clone and Setup
```bash
git clone https://github.com/zacharystevens/hello-world-honeypot.git
cd hello-world-honeypot

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Create Lambda Packages
```bash
# Create the refactored honeypot package
python scripts/package_lambda.py

# Verify packages created
ls -la *.zip
# Should show: honeypot_lambda.zip, lambda_function.zip
```

### 3. Deploy Infrastructure
```bash
# Initialize Terraform
terraform init

# Review deployment plan
terraform plan

# Deploy (takes ~2-3 minutes)
terraform apply -auto-approve
```

### 4. Verify Deployment
```bash
# Get deployment outputs
terraform output

# Test the honeypot endpoints
HONEYPOT_URL=$(terraform output -raw honeypot_api_endpoint)
curl -s "$HONEYPOT_URL/admin" | head -5
```

## Advanced Deployment Options

### Custom Configuration
```bash
# Deploy to different region
terraform apply -var="aws_region=us-east-1"

# Custom bucket naming
terraform apply -var="honeypot_bucket_suffix=prod"
```

### Production Deployment
```bash
# Use production-ready settings
terraform apply -var-file="environments/production.tfvars"
```

## Monitoring Deployment

### CloudWatch Logs
```bash
# Monitor real-time logs
aws logs tail /aws/lambda/honeypot --follow

# Check recent interactions
aws logs filter-log-events \
  --log-group-name /aws/lambda/honeypot \
  --start-time $(date -d '1 hour ago' +%s)000
```

### Health Checks
```bash
# Verify Lambda function status
aws lambda get-function --function-name honeypot-lambda

# Check API Gateway status
aws apigatewayv2 get-apis --query 'Items[?Name==`honeypot-api`]'
```

## Troubleshooting

### Common Issues

#### 1. Lambda Package Not Found
```bash
Error: source_code_hash = filebase64sha256("honeypot_lambda.zip")
       Call to function "filebase64sha256" failed: open honeypot_lambda.zip: no such file or directory
```
**Solution**: Run the packaging script first:
```bash
python scripts/package_lambda.py
```

#### 2. IAM Permission Errors
```bash
Error: creating Lambda Function: AccessDeniedException
```
**Solution**: Ensure your AWS credentials have the required permissions:
```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name YOUR_USERNAME
```

#### 3. State Drift Issues
```bash
Error: ResourceAlreadyExistsException: Role already exists
```
**Solution**: Import existing resources or delete them:
```bash
terraform import aws_iam_role.honeypot_lambda_role honeypot_lambda_role
# OR
aws iam delete-role --role-name honeypot_lambda_role
```

### Cleanup

#### Destroy Infrastructure
```bash
# Remove all AWS resources
terraform destroy -auto-approve
```

#### Clean Local Files
```bash
# Remove generated packages
rm -f *.zip

# Clean Terraform state (optional)
rm -rf .terraform terraform.tfstate*
```

## Security Considerations

### Production Hardening
1. **IAM Roles**: Use least-privilege principles
2. **Encryption**: Enable S3 bucket encryption (already configured)
3. **Logging**: Ensure CloudWatch retention is appropriate
4. **Monitoring**: Set up CloudWatch alarms for suspicious activity

### Network Security
1. **API Gateway**: Consider adding AWS WAF
2. **Lambda**: Review VPC configuration if needed
3. **S3**: Ensure bucket policies are restrictive

## Performance Optimization

### Lambda Configuration
- **Memory**: 256MB (adequate for current workload)
- **Timeout**: 30 seconds (sufficient for honeypot responses)
- **Concurrency**: Default (adjust based on expected traffic)

### Cost Management
- **S3 Lifecycle**: Configure object expiration for logs
- **CloudWatch**: Set appropriate log retention periods
- **Lambda**: Monitor invocation counts and duration

---

**Deployment Status**: ✅ Production Ready  
**Estimated Deploy Time**: 2-3 minutes  
**Estimated Costs**: $0.50-2.00/month (typical honeypot traffic)
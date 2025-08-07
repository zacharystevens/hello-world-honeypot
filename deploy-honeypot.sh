#!/bin/bash

# Function to display usage
usage() {
    echo "🍯 Honeypot Infrastructure Management Script"
    echo ""
    echo "Usage: $0 [deploy|remove|status]"
    echo ""
    echo "Commands:"
    echo "  deploy  - Deploy the honeypot infrastructure"
    echo "  remove  - Completely remove all AWS resources and clean up"
    echo "  status  - Check current deployment status"
    echo ""
    exit 1
}

# Function to get S3 bucket names from Terraform output or state
get_bucket_names() {
    echo "📋 Identifying S3 buckets..."
    
    # Try to get from terraform output first
    LAMBDA_BUCKET=$(terraform output -raw s3_bucket_name 2>/dev/null || echo "")
    HONEYPOT_BUCKET=$(terraform output -raw honeypot_data_bucket 2>/dev/null || echo "")
    
    # If outputs don't work, try to extract from state file
    if [[ -z "$LAMBDA_BUCKET" && -f "terraform.tfstate" ]]; then
        LAMBDA_BUCKET=$(grep -o '"hello-world-lambda-bucket-[^"]*"' terraform.tfstate | head -1 | tr -d '"' || echo "")
    fi
    
    if [[ -z "$HONEYPOT_BUCKET" && -f "terraform.tfstate" ]]; then
        HONEYPOT_BUCKET=$(grep -o '"honeypot-data-[^"]*"' terraform.tfstate | head -1 | tr -d '"' || echo "")
    fi
    
    # If still empty, try to find buckets with our naming pattern
    if [[ -z "$LAMBDA_BUCKET" ]]; then
        LAMBDA_BUCKET=$(aws s3 ls | grep "hello-world-lambda-bucket-" | awk '{print $3}' | head -1 || echo "")
    fi
    
    if [[ -z "$HONEYPOT_BUCKET" ]]; then
        HONEYPOT_BUCKET=$(aws s3 ls | grep "honeypot-data-" | awk '{print $3}' | head -1 || echo "")
    fi
    
    echo "🪣 Lambda Bucket: ${LAMBDA_BUCKET:-'Not found'}"
    echo "🪣 Honeypot Bucket: ${HONEYPOT_BUCKET:-'Not found'}"
}

# Function to completely empty an S3 bucket (including all versions)
empty_s3_bucket() {
    local bucket_name=$1
    
    if [[ -z "$bucket_name" ]]; then
        echo "⚠  No bucket name provided to empty_s3_bucket function"
        return 1
    fi
    
    echo "[DELETE]  Emptying S3 bucket: $bucket_name"
    
    # Check if bucket exists
    if ! aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        echo "ℹ  Bucket $bucket_name does not exist or is not accessible"
        return 0
    fi
    
    # Delete all object versions
    echo "   Deleting all object versions..."
    aws s3api list-object-versions --bucket "$bucket_name" --output json | \
    jq -r '.Versions[]? | .Key + " " + .VersionId' | \
    while read -r key version_id; do
        if [[ -n "$key" && -n "$version_id" && "$version_id" != "null" ]]; then
            aws s3api delete-object --bucket "$bucket_name" --key "$key" --version-id "$version_id" >/dev/null 2>&1
            echo "     Deleted version: $key ($version_id)"
        fi
    done
    
    # Delete all delete markers
    echo "   Deleting all delete markers..."
    aws s3api list-object-versions --bucket "$bucket_name" --output json | \
    jq -r '.DeleteMarkers[]? | .Key + " " + .VersionId' | \
    while read -r key version_id; do
        if [[ -n "$key" && -n "$version_id" && "$version_id" != "null" ]]; then
            aws s3api delete-object --bucket "$bucket_name" --key "$key" --version-id "$version_id" >/dev/null 2>&1
            echo "     Deleted delete marker: $key ($version_id)"
        fi
    done
    
    # Final cleanup - remove any remaining objects
    echo "   Final cleanup of remaining objects..."
    aws s3 rm "s3://$bucket_name" --recursive >/dev/null 2>&1
    
    echo "✓ Bucket $bucket_name is now empty"
}

# Function to clean up CloudWatch log groups
cleanup_log_groups() {
    echo "🧹 Cleaning up CloudWatch log groups..."
    
    local log_groups=(
        "/aws/api_gw/hello-world-api"
        "/aws/lambda/hello_world_lambda"
        "/aws/lambda/honeypot"
        "/aws/lambda/honeypot-lambda"
        "/aws/apigateway/honeypot"
    )
    
    for log_group in "${log_groups[@]}"; do
        if aws logs describe-log-groups --log-group-name-prefix "$log_group" --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$log_group"; then
            echo "   Deleting log group: $log_group"
            aws logs delete-log-group --log-group-name "$log_group" 2>/dev/null || echo "     Failed to delete $log_group (may not exist)"
        fi
    done
}

# Function to deploy infrastructure
deploy() {
    echo "🍯 Deploying Honeypot Infrastructure..."
    
    # Create honeypot Lambda package
    echo "📦 Creating Lambda deployment package..."
    zip -r honeypot_lambda.zip honeypot_lambda.py
    
    # Deploy infrastructure
    echo "[DEPLOY] Deploying Terraform infrastructure..."
    terraform init
    terraform plan -out=honeypot.tfplan
    terraform apply honeypot.tfplan
    
    # Get the API endpoint
    HONEYPOT_ENDPOINT=$(terraform output -raw honeypot_api_endpoint 2>/dev/null || echo "Unable to retrieve endpoint")
    
    echo ""
    echo "✓ Honeypot deployed successfully!"
    echo "🔗 Honeypot URL: $HONEYPOT_ENDPOINT"
    echo "[DATA] Monitor logs: aws logs tail /aws/lambda/honeypot --follow"
    echo "📈 View metrics: AWS CloudWatch Console -> Honeypot/Interactions"
    
    # Display S3 bucket information
    get_bucket_names
    
    echo ""
    echo "[TIP] Consider setting up these DNS records to attract attackers:"
    echo "   - admin.\$YOUR_DOMAIN -> $HONEYPOT_ENDPOINT"
    echo "   - api.\$YOUR_DOMAIN -> $HONEYPOT_ENDPOINT"
    echo "   - staging.\$YOUR_DOMAIN -> $HONEYPOT_ENDPOINT"
    echo ""
    echo "[DELETE]  To completely remove all resources later, run: $0 remove"
}

# Function to remove all infrastructure
remove() {
    echo "[DELETE]  REMOVING ALL HONEYPOT INFRASTRUCTURE"
    echo "⚠  This will permanently delete all AWS resources and data!"
    echo ""
    
    # Get bucket names before destroying
    get_bucket_names
    
    echo ""
    read -p "Are you sure you want to proceed? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "✗ Removal cancelled"
        exit 0
    fi
    
    echo ""
    echo "🧹 Starting complete cleanup process..."
    
    # Step 1: Empty S3 buckets
    echo ""
    echo "📦 Step 1: Emptying S3 buckets..."
    if [[ -n "$LAMBDA_BUCKET" ]]; then
        empty_s3_bucket "$LAMBDA_BUCKET"
    fi
    
    if [[ -n "$HONEYPOT_BUCKET" ]]; then
        empty_s3_bucket "$HONEYPOT_BUCKET"
    fi
    
    # Step 2: Clean up CloudWatch log groups
    echo ""
    echo "📋 Step 2: Cleaning up CloudWatch log groups..."
    cleanup_log_groups
    
    # Step 3: Run terraform destroy
    echo ""
    echo "[BUILD]  Step 3: Destroying Terraform infrastructure..."
    if [[ -f "terraform.tfstate" ]]; then
        terraform destroy -auto-approve
    else
        echo "ℹ  No terraform.tfstate file found - infrastructure may already be destroyed"
    fi
    
    # Step 4: Clean up local files
    echo ""
    echo "🧽 Step 4: Cleaning up local files..."
    rm -f terraform.tfstate terraform.tfstate.backup
    rm -f honeypot_lambda.zip lambda_function.zip
    rm -f honeypot.tfplan plan-cli.out response.json
    
    # Step 5: Final verification
    echo ""
    echo "🔍 Step 5: Final verification..."
    
    # Check for any remaining buckets
    remaining_buckets=$(aws s3 ls | grep -E "(hello-world-lambda-bucket|honeypot-data)" || echo "")
    if [[ -n "$remaining_buckets" ]]; then
        echo "⚠  Warning: Some S3 buckets may still exist:"
        echo "$remaining_buckets"
    else
        echo "✓ No S3 buckets found with our naming pattern"
    fi
    
    # Check for any remaining Lambda functions
    remaining_lambdas=$(aws lambda list-functions --query 'Functions[?contains(FunctionName, `hello`) || contains(FunctionName, `honeypot`)] | length(@)' --output text 2>/dev/null || echo "")
    if [[ -n "$remaining_lambdas" && "$remaining_lambdas" != "None" ]]; then
        echo "⚠  Warning: Some Lambda functions may still exist: $remaining_lambdas"
    else
        echo "✓ No Lambda functions found with our naming pattern"
    fi
    
    echo ""
    echo "🎉 CLEANUP COMPLETE!"
    echo "💰 Your AWS account should now have zero charges from this infrastructure"
    echo "🔒 All honeypot resources have been removed"
}

# Function to check status
status() {
    echo "[DATA] Checking Honeypot Infrastructure Status..."
    echo ""
    
    if [[ -f "terraform.tfstate" ]]; then
        echo "📋 Terraform State: Found"
        terraform state list 2>/dev/null || echo "   No resources in state"
    else
        echo "📋 Terraform State: Not found"
    fi
    
    echo ""
    get_bucket_names
    
    echo ""
    echo "🔍 AWS Resource Check:"
    
    # Check Lambda functions
    lambda_count=$(aws lambda list-functions --query 'Functions[?contains(FunctionName, `hello`) || contains(FunctionName, `honeypot`)] | length(@)' --output text 2>/dev/null || echo "0")
    echo "   Lambda Functions: $lambda_count"
    
    # Check API Gateways
    api_count=$(aws apigatewayv2 get-apis --query 'Items[?contains(Name, `hello`) || contains(Name, `honeypot`)] | length(@)' --output text 2>/dev/null || echo "0")
    echo "   API Gateways: $api_count"
    
    # Check CloudWatch Log Groups
    log_count=$(aws logs describe-log-groups --query 'logGroups[?contains(logGroupName, `hello`) || contains(logGroupName, `honeypot`)] | length(@)' --output text 2>/dev/null || echo "0")
    echo "   CloudWatch Log Groups: $log_count"
}

# Main script logic
case "${1:-}" in
    deploy)
        deploy
        ;;
    remove)
        remove
        ;;
    status)
        status
        ;;
    *)
        usage
        ;;
esac 
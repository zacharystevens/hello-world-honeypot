# Hello world lambda

# collision avoidance for S3 bucket name
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket for Lambda deployment package
resource "aws_s3_bucket" "lambda_bucket" {
  bucket = "hello-world-lambda-bucket-${random_string.bucket_suffix.result}"
}

resource "aws_s3_bucket_ownership_controls" "lambda_bucket_ownership" {
  bucket = aws_s3_bucket.lambda_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "lambda_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.lambda_bucket_ownership]

  bucket = aws_s3_bucket.lambda_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "lambda_bucket_versioning" {
  bucket = aws_s3_bucket.lambda_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lambda_bucket_encryption" {
  bucket = aws_s3_bucket.lambda_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Upload Lambda zip package to S3
resource "aws_s3_object" "lambda_zip" {
  bucket = aws_s3_bucket.lambda_bucket.id
  key    = var.lambda_zip_file
  source = var.lambda_zip_file
  etag   = filemd5(var.lambda_zip_file)
}

# Null resource to handle S3 bucket cleanup
resource "null_resource" "s3_bucket_cleanup" {
  triggers = {
    bucket_id = aws_s3_bucket.lambda_bucket.id
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<EOF
      aws s3api list-object-versions --bucket ${self.triggers.bucket_id} --output json --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}} + {Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' | jq -r '.Objects[] | .Key + " " + .VersionId' | while read key version; do
        aws s3api delete-object --bucket ${self.triggers.bucket_id} --key "$key" --version-id "$version"
      done
    EOF
  }
}

# IAM Role for Lambda
data "aws_iam_role" "existing_lambda_exec_role" {
  name  = "lambda_exec_role"
  count = 1
}

resource "aws_iam_role" "lambda_exec_role" {
  count = data.aws_iam_role.existing_lambda_exec_role[0].id == null ? 1 : 0
  name  = "lambda_exec_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

locals {
  lambda_exec_role_arn = data.aws_iam_role.existing_lambda_exec_role[0].id != null ? data.aws_iam_role.existing_lambda_exec_role[0].arn : aws_iam_role.lambda_exec_role[0].arn
}

# IAM Policy for Lambda to write logs to CloudWatch
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda_cloudwatch_policy"
  role = data.aws_iam_role.existing_lambda_exec_role[0].id != null ? data.aws_iam_role.existing_lambda_exec_role[0].id : aws_iam_role.lambda_exec_role[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Effect   = "Allow"
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}

# Lambda Function
resource "aws_lambda_function" "hello_world_lambda" {
  function_name    = "hello_world_lambda"
  filename         = var.lambda_zip_file
  source_code_hash = filebase64sha256(var.lambda_zip_file)
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  role             = local.lambda_exec_role_arn
  memory_size      = 128
  timeout          = 10

  environment {
    variables = {
      MESSAGE = "Hello World!"
    }
  }
}

# API Gateway to expose Lambda function via HTTP
resource "aws_apigatewayv2_api" "http_api" {
  name          = "hello-world-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.hello_world_lambda.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_apigatewayv2_stage" "default_stage" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw_lambda" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.hello_world_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# CloudWatch Log Group for API Gateway
data "aws_cloudwatch_log_group" "existing_api_gw" {
  name  = "/aws/api_gw/${aws_apigatewayv2_api.http_api.name}"
  count = 1
}

resource "aws_cloudwatch_log_group" "api_gw" {
  count             = length(data.aws_cloudwatch_log_group.existing_api_gw) == 0 ? 1 : 0
  name              = "/aws/api_gw/${aws_apigatewayv2_api.http_api.name}"
  retention_in_days = 30
}

locals {
  cloudwatch_log_group_arn = data.aws_cloudwatch_log_group.existing_api_gw[0].arn != null ? data.aws_cloudwatch_log_group.existing_api_gw[0].arn : aws_cloudwatch_log_group.api_gw[0].arn
}

# Enable detailed CloudWatch metrics for API Gateway
resource "aws_apigatewayv2_stage" "example" {
  api_id = aws_apigatewayv2_api.http_api.id
  name   = "example-stage"

  access_log_settings {
    destination_arn = local.cloudwatch_log_group_arn
    format          = "$context.identity.sourceIp - - [$context.requestTime] \"$context.httpMethod $context.routeKey $context.protocol\" $context.status $context.responseLength $context.requestId $context.integrationErrorMessage"
  }
}

# IAM User and Policy for Lambda execution
data "aws_iam_user" "lambda_user" {
  user_name = "lambda_stooge"
}

resource "aws_iam_policy" "lambda_user_policy" {
  name        = "lambda_user_policy"
  description = "Policy for lambda_user to execute the hello-world Lambda function"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.hello_world_lambda.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "lambda_user_policy_attach" {
  user       = data.aws_iam_user.lambda_user.user_name
  policy_arn = aws_iam_policy.lambda_user_policy.arn
}

resource "aws_iam_access_key" "lambda_user_key" {
  user = data.aws_iam_user.lambda_user.user_name
}


# Outputs
output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = aws_apigatewayv2_stage.default_stage.invoke_url
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.hello_world_lambda.function_name
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket used for Lambda deployment package"
  value       = aws_s3_bucket.lambda_bucket.id
}

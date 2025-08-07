# Enhanced honeypot infrastructure

# CloudWatch Log Group for honeypot logs
resource "aws_cloudwatch_log_group" "honeypot_logs" {
  name              = "/aws/lambda/honeypot"
  retention_in_days = 90

  tags = {
    Environment = "honeypot"
    Purpose     = "security-monitoring"
  }
}

# S3 bucket for storing detailed honeypot data
resource "aws_s3_bucket" "honeypot_data" {
  bucket = "honeypot-data-${random_string.bucket_suffix.result}"

  tags = {
    Environment = "honeypot"
    Purpose     = "threat-intelligence"
  }
}

resource "aws_s3_bucket_versioning" "honeypot_data_versioning" {
  bucket = aws_s3_bucket.honeypot_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "honeypot_data_encryption" {
  bucket = aws_s3_bucket.honeypot_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lambda function for honeypot
resource "aws_lambda_function" "honeypot_lambda" {
  function_name    = "honeypot-lambda"
  filename         = "honeypot_lambda.zip"
  source_code_hash = filebase64sha256("honeypot_lambda.zip")
  handler          = "honeypot_lambda.lambda_handler"
  runtime          = "python3.9"
  role             = aws_iam_role.honeypot_lambda_role.arn
  memory_size      = 256
  timeout          = 30

  environment {
    variables = {
      HONEYPOT_BUCKET = aws_s3_bucket.honeypot_data.bucket
      LOG_LEVEL       = "INFO"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.honeypot_lambda_logs,
    aws_cloudwatch_log_group.honeypot_logs,
  ]

  tags = {
    Environment = "honeypot"
    Purpose     = "security-monitoring"
  }
}

# Enhanced IAM role for honeypot Lambda
resource "aws_iam_role" "honeypot_lambda_role" {
  name = "honeypot_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for honeypot Lambda
resource "aws_iam_policy" "honeypot_lambda_policy" {
  name        = "honeypot_lambda_policy"
  description = "IAM policy for honeypot lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.honeypot_data.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "honeypot_lambda_logs" {
  role       = aws_iam_role.honeypot_lambda_role.name
  policy_arn = aws_iam_policy.honeypot_lambda_policy.arn
}

# API Gateway for honeypot
resource "aws_apigatewayv2_api" "honeypot_api" {
  name          = "honeypot-api"
  protocol_type = "HTTP"
  description   = "Honeypot API Gateway"

  cors_configuration {
    allow_credentials = false
    allow_headers     = ["*"]
    allow_methods     = ["*"]
    allow_origins     = ["*"]
    expose_headers    = ["*"]
    max_age           = 86400
  }
}

resource "aws_apigatewayv2_integration" "honeypot_integration" {
  api_id                 = aws_apigatewayv2_api.honeypot_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.honeypot_lambda.invoke_arn
  payload_format_version = "2.0"
}

# Catch-all route to capture all requests
resource "aws_apigatewayv2_route" "honeypot_catch_all" {
  api_id    = aws_apigatewayv2_api.honeypot_api.id
  route_key = "ANY /{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.honeypot_integration.id}"
}

# Default route
resource "aws_apigatewayv2_route" "honeypot_default" {
  api_id    = aws_apigatewayv2_api.honeypot_api.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.honeypot_integration.id}"
}

resource "aws_apigatewayv2_stage" "honeypot_stage" {
  api_id      = aws_apigatewayv2_api.honeypot_api.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.honeypot_api_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      userAgent      = "$context.identity.userAgent"
    })
  }

  default_route_settings {
    detailed_metrics_enabled = true
    throttling_burst_limit   = 100
    throttling_rate_limit    = 50
  }
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "honeypot_api_logs" {
  name              = "/aws/apigateway/honeypot"
  retention_in_days = 90
}

resource "aws_lambda_permission" "honeypot_apigw_lambda" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeypot_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.honeypot_api.execution_arn}/*/*"
}

# CloudWatch Alarms for threat detection
resource "aws_cloudwatch_metric_alarm" "high_interaction_rate" {
  alarm_name          = "honeypot-high-interaction-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TotalInteractions"
  namespace           = "Honeypot/Interactions"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "This metric monitors high interaction rates with honeypot"
  alarm_actions       = [aws_sns_topic.honeypot_alerts.arn]
}

# SNS topic for alerts
resource "aws_sns_topic" "honeypot_alerts" {
  name = "honeypot-alerts"
}

# Outputs
output "honeypot_api_endpoint" {
  description = "API Gateway endpoint URL for honeypot"
  value       = aws_apigatewayv2_api.honeypot_api.api_endpoint
}

output "honeypot_data_bucket" {
  description = "S3 bucket for honeypot data storage"
  value       = aws_s3_bucket.honeypot_data.bucket
}

output "honeypot_logs_group" {
  description = "CloudWatch log group for honeypot logs"
  value       = aws_cloudwatch_log_group.honeypot_logs.name
}

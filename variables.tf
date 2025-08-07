# variables.tf

## Hello World Lambda

variable "aws_region" {
  description = "The AWS region where resources will be deployed"
  type        = string
  default     = "us-west-2"
}

variable "lambda_zip_file" {
  description = "The path to the Lambda deployment zip file"
  type        = string
  default     = "lambda_function.zip"
}


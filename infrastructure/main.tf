provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "lambda_exec" {
  name = "spectre_lambda_exec_role"

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

resource "aws_lambda_function" "spectre_node" {
  count         = 10
  function_name = "spectre-node-${count.index}"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "bootstrap" # For provided.al2 runtime
  runtime       = "provided.al2"

  # Placeholder for the actual binary zip
  filename      = "function.zip" 
  
  # Environment variables for configuration
  environment {
    variables = {
      RUST_LOG = "info"
    }
  }
}

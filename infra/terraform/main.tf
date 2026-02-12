terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. S3 Log Bucket for CloudTrail
resource "aws_s3_bucket" "log_bucket" {
  bucket_prefix = "cloud-ir-lab-logs-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "log_bucket_access" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_encryption" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "log_bucket_lifecycle" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    id     = "expire_logs"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}

# Policy to allow CloudTrail to write to the bucket
resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket = aws_s3_bucket.log_bucket.id
  policy = data.aws_iam_policy_document.log_bucket_policy.json
}

data.aws_iam_policy_document "log_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_bucket.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# 2. CloudTrail
resource "aws_cloudtrail" "main" {
  name                          = "cloud-ir-lab-trail"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

# 3. GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# 4. IAM User "ir-lab-suspect"
resource "aws_iam_user" "suspect" {
  name = "ir-lab-suspect"
}

resource "aws_iam_access_key" "suspect_key" {
  user = aws_iam_user.suspect.name
}

# 5. Test Data Bucket & Object
resource "aws_s3_bucket" "test_data" {
  bucket_prefix = "cloud-ir-lab-testdata-"
  force_destroy = true
}

resource "aws_s3_object" "canary" {
  bucket  = aws_s3_bucket.test_data.id
  key     = "canary.txt"
  content = "cloud-ir-lab canary"
}

# IAM Policy for Suspect
resource "aws_iam_user_policy" "suspect_policy" {
  name = "ir-lab-suspect-policy"
  user = aws_iam_user.suspect.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRecon"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "iam:ListUsers",
          "iam:ListRoles",
          "s3:ListAllMyBuckets",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },
      {
        Sid    = "ExplicitDenySensitive"
        Effect = "Deny"
        Action = [
          "s3:GetObject",
          "iam:CreateUser",
          "ec2:TerminateInstances"
        ]
        Resource = [
          "${aws_s3_bucket.test_data.arn}/canary.txt",
          "*" # For global actions like IAM/EC2 where resource constraints apply generally or we want to deny specific actions globally
        ]
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

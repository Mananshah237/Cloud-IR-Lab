output "log_bucket_name" {
  value = aws_s3_bucket.log_bucket.id
}

output "testdata_bucket_name" {
  value = aws_s3_bucket.test_data.id
}

output "suspect_user_name" {
  value = aws_iam_user.suspect.name
}

output "suspect_access_key_id" {
  value = aws_iam_access_key.suspect_key.id
}

# Sensitive — retrieve with: terraform output -raw suspect_secret_access_key
# Used to configure the `ir-lab-suspect` AWS CLI profile for the attack scripts.
output "suspect_secret_access_key" {
  value     = aws_iam_access_key.suspect_key.secret
  sensitive = true
}


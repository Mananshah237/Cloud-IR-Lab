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


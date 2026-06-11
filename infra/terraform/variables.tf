variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "enable_guardduty" {
  description = "Enable the GuardDuty detector. Off by default to keep the lab at $0; GuardDuty is the only resource that can incur charges."
  type        = bool
  default     = false
}

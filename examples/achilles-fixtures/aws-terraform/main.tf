resource "aws_security_group_rule" "fixture" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_s3_bucket" "fixture" {
  bucket = "achilles-fixture"
  acl    = "public-read"
}

resource "aws_db_instance" "fixture" {
  publicly_accessible   = true
  skip_final_snapshot   = true
}

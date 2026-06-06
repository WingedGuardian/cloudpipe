resource "aws_db_subnet_group" "main" {
  name       = "cloudpipe-${var.environment}"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "db" {
  name   = "cloudpipe-${var.environment}-db"
  vpc_id = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_sg_id]
  }
}

resource "aws_db_instance" "main" {
  identifier     = "cloudpipe-${var.environment}"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.t4g.micro" # arm64, cheapest option

  allocated_storage = 20
  storage_encrypted = true

  db_name  = "cloudpipe"
  username = "cloudpipe"
  # RDS manages the password via Secrets Manager automatically
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  skip_final_snapshot       = false
  final_snapshot_identifier = "cloudpipe-${var.environment}-final-snapshot"
  multi_az                  = false

  tags = { Name = "cloudpipe-${var.environment}" }
}

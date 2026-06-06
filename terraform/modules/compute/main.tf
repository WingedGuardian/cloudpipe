resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/cloudpipe-${var.environment}"
  retention_in_days = 30
}

# ALB--public-facing, terminates HTTP (HTTPS needs a cert, skip for demo)
resource "aws_security_group" "alb" {
  name   = "cloudpipe-${var.environment}-alb"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "main" {
  name               = "cloudpipe-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "app" {
  name        = "cloudpipe-${var.environment}-app"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Production: add aws_lb_listener.https with var.certificate_arn
# HTTPS requires ACM certificate validation against a registered domain
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ECS cluster + Fargate service
resource "aws_ecs_cluster" "main" {
  name = "cloudpipe-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_security_group" "app" {
  name   = "cloudpipe-${var.environment}-app"
  vpc_id = var.vpc_id

  # only ALB can reach the container
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = "cloudpipe-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  runtime_platform {
    operating_system_family = "LINUX"
    # X86_64 for build simplicity; ARM64 (Graviton) is the production optimization path
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name  = "app"
    image = var.container_image
    portMappings = [{
      containerPort = 8000
      protocol      = "tcp"
    }]
    environment = [
      { name = "DB_HOST", value = var.db_endpoint },
      { name = "ENVIRONMENT", value = var.environment },
    ]
    secrets = [
      { name = "DB_PASSWORD", valueFrom = var.db_secret_arn },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "app"
      }
    }
  }])
}

resource "aws_ecs_service" "app" {
  name            = "cloudpipe-${var.environment}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.app.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = 8000
  }
}

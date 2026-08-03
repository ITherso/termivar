terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }

  # Uncomment for remote state
  # backend "s3" {
  #   bucket         = "venom-terraform-state"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "VENOM"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_auth.cluster.token
  }
}

data "aws_eks_auth" "cluster" {
  name = module.eks.cluster_name
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"

  environment = var.environment
  cidr_block  = var.vpc_cidr_block

  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs

  enable_nat_gateway = true
  enable_vpn_gateway = false
}

# EKS Module
module "eks" {
  source = "./modules/eks"

  environment = var.environment
  cluster_name = "venom-${var.environment}"

  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids
  control_plane_subnet_ids = module.vpc.public_subnet_ids

  desired_size = var.eks_desired_size
  min_size     = var.eks_min_size
  max_size     = var.eks_max_size

  instance_types = var.eks_instance_types
}

# RDS PostgreSQL Module
module "rds" {
  source = "./modules/rds"

  environment = var.environment
  db_name     = "venom_db"

  db_username = var.db_username
  db_password = var.db_password

  vpc_id            = module.vpc.vpc_id
  db_subnet_ids     = module.vpc.private_subnet_ids

  allocated_storage    = var.db_allocated_storage
  storage_type         = "gp3"
  instance_class       = "db.t3.medium"

  skip_final_snapshot       = var.environment != "prod"
  backup_retention_period   = var.db_backup_retention_days
  multi_az                  = var.environment == "prod"
}

# ElastiCache Redis Module
module "redis" {
  source = "./modules/elasticache"

  environment = var.environment
  cluster_id  = "venom-${var.environment}"

  engine_version      = "7.0"
  node_type           = var.redis_node_type
  num_cache_nodes     = var.redis_num_nodes

  parameter_group_name = "default.redis7"
  engine_name          = "redis"

  vpc_id           = module.vpc.vpc_id
  subnet_ids       = module.vpc.private_subnet_ids
  security_group_ids = [aws_security_group.redis.id]

  automatic_failover_enabled = var.environment == "prod"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

# Security Groups
resource "aws_security_group" "redis" {
  name        = "venom-redis-${var.environment}"
  description = "Security group for VENOM Redis cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_worker.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr_block]
  }

  tags = {
    Name = "venom-redis-${var.environment}"
  }
}

resource "aws_security_group" "eks_worker" {
  name        = "venom-eks-worker-${var.environment}"
  description = "Security group for EKS worker nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr_block]
  }

  tags = {
    Name = "venom-eks-worker-${var.environment}"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "venom" {
  name              = "/aws/eks/venom-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "venom-${var.environment}"
  }
}

# Outputs
output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name"
}

output "eks_cluster_endpoint" {
  value       = module.eks.cluster_endpoint
  description = "EKS cluster endpoint"
}

output "rds_endpoint" {
  value       = module.rds.db_endpoint
  description = "RDS database endpoint"
}

output "redis_endpoint" {
  value       = module.redis.cluster_address
  description = "Redis cluster endpoint"
}

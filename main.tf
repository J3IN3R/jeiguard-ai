# JeiGuard AI v1.0.2 — Cloud-Native Deployment
# Terraform + Helm para AWS EKS con auto-scaling y alta disponibilidad
# Copyright © 2026 Jeiner Tello Nuñez — MIT License
# ──────────────────────────────────────────────────────────────────────────────
# USO:
#   cd cloud_deploy/terraform
#   terraform init
#   terraform plan -var="environment=production"
#   terraform apply -auto-approve
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "s3" {
    bucket  = "jeiguard-ai-terraform-state"
    key     = "production/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "environment"    { default = "production" }
variable "aws_region"     { default = "us-east-1" }
variable "cluster_name"   { default = "jeiguard-ai-eks" }
variable "node_type"      { default = "t3.xlarge" }
variable "min_nodes"      { default = 2 }
variable "max_nodes"      { default = 20 }
variable "desired_nodes"  { default = 3 }

# ── Provider ──────────────────────────────────────────────────────────────────
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "JeiGuard-AI"
      Version     = "1.0.2"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Jeiner Tello Nuñez"
    }
  }
}

# ── Networking ────────────────────────────────────────────────────────────────
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "jeiguard-ai-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true
  enable_dns_hostnames   = true
  enable_dns_support     = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# ── EKS Cluster ───────────────────────────────────────────────────────────────
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  eks_managed_node_groups = {
    # Nodos para servicios de inferencia (CPU-optimizados)
    inference = {
      name           = "inference-nodes"
      instance_types = [var.node_type]
      min_size       = var.min_nodes
      max_size       = var.max_nodes
      desired_size   = var.desired_nodes

      labels = {
        role    = "inference"
        project = "jeiguard-ai"
      }

      taints = []

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 100
            volume_type           = "gp3"
            iops                  = 3000
            encrypted             = true
            delete_on_termination = true
          }
        }
      }
    }

    # Nodos para Kafka y Elasticsearch (almacenamiento-optimizados)
    storage = {
      name           = "storage-nodes"
      instance_types = ["r5.2xlarge"]
      min_size       = 3
      max_size       = 9
      desired_size   = 3

      labels = {
        role    = "storage"
        project = "jeiguard-ai"
      }
    }
  }

  cluster_addons = {
    coredns                = { most_recent = true }
    kube-proxy             = { most_recent = true }
    vpc-cni                = { most_recent = true }
    aws-ebs-csi-driver     = { most_recent = true }
  }
}

# ── MSK (Kafka Gestionado) ────────────────────────────────────────────────────
resource "aws_msk_cluster" "jeiguard_kafka" {
  cluster_name           = "jeiguard-ai-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.xlarge"
    client_subnets  = module.vpc.private_subnets
    storage_info {
      ebs_storage_info { volume_size = 500 }
    }
    security_groups = [aws_security_group.kafka.id]
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.jeiguard.arn
    revision = aws_msk_configuration.jeiguard.latest_revision
  }
}

resource "aws_msk_configuration" "jeiguard" {
  name              = "jeiguard-ai-kafka-config"
  kafka_versions    = ["3.6.0"]
  server_properties = <<EOF
auto.create.topics.enable=true
default.replication.factor=3
min.insync.replicas=2
num.partitions=6
log.retention.hours=168
message.max.bytes=1048576
EOF
}

# ── Elasticsearch (OpenSearch Gestionado) ─────────────────────────────────────
resource "aws_opensearch_domain" "jeiguard" {
  domain_name    = "jeiguard-ai-alerts"
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type          = "r6g.2xlarge.search"
    instance_count         = 3
    zone_awareness_enabled = true
    zone_awareness_config  { availability_zone_count = 3 }
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 500
    iops        = 3000
    throughput  = 125
  }

  encrypt_at_rest { enabled = true }
  node_to_node_encryption { enabled = true }

  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = true
  }

  snapshot_options { automated_snapshot_start_hour = 3 }
}

# ── Security Groups ───────────────────────────────────────────────────────────
resource "aws_security_group" "kafka" {
  name_prefix = "jeiguard-kafka-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 9094
    to_port     = 9094
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "eks_cluster_endpoint"    { value = module.eks.cluster_endpoint }
output "eks_cluster_name"        { value = module.eks.cluster_name }
output "kafka_bootstrap_brokers" { value = aws_msk_cluster.jeiguard_kafka.bootstrap_brokers_tls }
output "opensearch_endpoint"     { value = aws_opensearch_domain.jeiguard.endpoint }
output "vpc_id"                  { value = module.vpc.vpc_id }

# ══════════════════════════════════════════════════════════════════════════════
# terraform/azure/main.tf — JeiGuard AI Azure AKS Deployment
# Copyright © 2026 Jeiner Tello Nuñez — MIT License
# ══════════════════════════════════════════════════════════════════════════════
#
# Infraestructura en Microsoft Azure:
#   • AKS Cluster (Azure Kubernetes Service) — producción grade
#   • Azure Event Hubs (equivalente Kafka managed)
#   • Azure Database for PostgreSQL Flexible Server
#   • Azure Cache for Redis
#   • Azure Container Registry (ACR)
#   • Azure Application Insights (APM)
#   • Azure Key Vault (secretos)
#   • Virtual Network con subnets privadas
#   • Azure Bastion (acceso seguro)
#   • Azure Monitor + Log Analytics
# ══════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "azurerm" {
    resource_group_name  = "jeiguard-tfstate-rg"
    storage_account_name = "jeiguardtfstate"
    container_name       = "tfstate"
    key                  = "jeiguard-ai.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "location" {
  type        = string
  default     = "eastus2"
  description = "Azure region para el despliegue"
}

variable "environment" {
  type        = string
  default     = "production"
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Debe ser development, staging o production."
  }
}

variable "aks_node_count" {
  type    = number
  default = 3
}

variable "aks_node_size" {
  type    = string
  default = "Standard_D4s_v3"
}

variable "aks_max_nodes" {
  type    = number
  default = 20
}

variable "postgres_sku" {
  type    = string
  default = "GP_Standard_D4s_v3"
}

variable "tags" {
  type = map(string)
  default = {
    Project     = "JeiGuard-AI"
    Version     = "2.0.0"
    ManagedBy   = "Terraform"
    Owner       = "jeiguard-team"
    CostCenter  = "security-ops"
  }
}

# ── Data Sources ──────────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

# ── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = "jeiguard-ai-${var.environment}-rg"
  location = var.location
  tags     = var.tags
}

# ── Log Analytics Workspace ───────────────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "main" {
  name                = "jeiguard-logs-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

# ── Virtual Network ───────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "main" {
  name                = "jeiguard-vnet-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/8"]
  tags                = var.tags
}

resource "azurerm_subnet" "aks_nodes" {
  name                 = "aks-nodes-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.1.0.0/16"]
}

resource "azurerm_subnet" "aks_pods" {
  name                 = "aks-pods-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.2.0.0/16"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "private-endpoints-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.3.0.0/24"]

  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.3.1.0/27"]
}

# ── Azure Container Registry ──────────────────────────────────────────────────

resource "azurerm_container_registry" "main" {
  name                = "jeiguardacr${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Premium"
  admin_enabled       = false
  georeplications = [
    {
      location                  = "westus2"
      zone_redundancy_enabled   = true
      regional_endpoint_enabled = true
      tags                      = {}
    }
  ]
  tags = var.tags
}

# ── Azure Key Vault ───────────────────────────────────────────────────────────

resource "azurerm_key_vault" "main" {
  name                       = "jeiguard-kv-${var.environment}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = var.tags
}

# ── AKS Cluster ───────────────────────────────────────────────────────────────

resource "azurerm_kubernetes_cluster" "main" {
  name                = "jeiguard-aks-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "jeiguard-${var.environment}"
  kubernetes_version  = "1.29"

  sku_tier = "Standard"

  default_node_pool {
    name                = "system"
    node_count          = var.aks_node_count
    vm_size             = var.aks_node_size
    min_count           = 2
    max_count           = var.aks_max_nodes
    enable_auto_scaling = true
    vnet_subnet_id      = azurerm_subnet.aks_nodes.id
    pod_subnet_id       = azurerm_subnet.aks_pods.id
    os_disk_size_gb     = 128
    type                = "VirtualMachineScaleSets"
    zones               = ["1", "2", "3"]

    node_labels = {
      "node-type" = "system"
      "project"   = "jeiguard-ai"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin     = "azure"
    network_policy     = "calico"
    load_balancer_sku  = "standard"
    outbound_type      = "userAssignedNATGateway"
    service_cidr       = "10.100.0.0/16"
    dns_service_ip     = "10.100.0.10"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  azure_policy_enabled = true

  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  tags = var.tags
}

resource "azurerm_kubernetes_cluster_node_pool" "inference" {
  name                  = "inference"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D8s_v3"
  min_count             = 2
  max_count             = 20
  enable_auto_scaling   = true
  vnet_subnet_id        = azurerm_subnet.aks_nodes.id
  zones                 = ["1", "2", "3"]

  node_labels = {
    "node-type"          = "inference"
    "jeiguard.ai/pool"   = "ml-inference"
  }

  node_taints = [
    "jeiguard.ai/workload=inference:NoSchedule"
  ]
}

# ── Azure Event Hubs (Kafka API compatible) ───────────────────────────────────

resource "azurerm_eventhub_namespace" "main" {
  name                     = "jeiguard-eventhubs-${var.environment}"
  location                 = azurerm_resource_group.main.location
  resource_group_name      = azurerm_resource_group.main.name
  sku                      = "Premium"
  capacity                 = 4
  kafka_enabled            = true
  zone_redundant           = true
  auto_inflate_enabled     = true
  maximum_throughput_units = 20
  tags                     = var.tags
}

locals {
  event_hubs = [
    "jeiguard.raw.flows",
    "jeiguard.processed.features",
    "jeiguard.predictions",
    "jeiguard.alerts",
    "jeiguard.dead.letter",
  ]
}

resource "azurerm_eventhub" "topics" {
  for_each            = toset(local.event_hubs)
  name                = replace(each.value, ".", "-")
  namespace_name      = azurerm_eventhub_namespace.main.name
  resource_group_name = azurerm_resource_group.main.name
  partition_count     = 4
  message_retention   = 1
}

# ── Azure Database for PostgreSQL ─────────────────────────────────────────────

resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "jeiguard-postgres-${var.environment}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "16"
  delegated_subnet_id    = azurerm_subnet.private_endpoints.id
  sku_name               = var.postgres_sku
  storage_mb             = 131072
  backup_retention_days  = 35
  geo_redundant_backup_enabled = true
  zone                   = "1"
  high_availability {
    mode                      = "ZoneRedundant"
    standby_availability_zone = "2"
  }
  administrator_login    = "jeiguard_admin"
  administrator_password = random_password.postgres.result
  tags                   = var.tags
}

resource "random_password" "postgres" {
  length  = 32
  special = true
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "jeiguard_ai"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# ── Azure Cache for Redis ─────────────────────────────────────────────────────

resource "azurerm_redis_cache" "main" {
  name                = "jeiguard-redis-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  capacity            = 2
  family              = "P"
  sku_name            = "Premium"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
  shard_count         = 2
  zones               = ["1", "2"]

  redis_configuration {
    maxmemory_reserved = 50
    maxmemory_delta    = 50
    maxmemory_policy   = "allkeys-lru"
  }

  tags = var.tags
}

# ── Application Insights ──────────────────────────────────────────────────────

resource "azurerm_application_insights" "main" {
  name                = "jeiguard-appinsights-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = var.tags
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "aks_kubeconfig" {
  value     = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive = true
}

output "acr_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "eventhub_connection_string" {
  value     = azurerm_eventhub_namespace.main.default_primary_connection_string
  sensitive = true
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.main.fqdn
}

output "redis_hostname" {
  value = azurerm_redis_cache.main.hostname
}

output "appinsights_connection_string" {
  value     = azurerm_application_insights.main.connection_string
  sensitive = true
}

output "key_vault_uri" {
  value = azurerm_key_vault.main.vault_uri
}

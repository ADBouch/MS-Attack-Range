variable "prefix" {
  description = "Prefix for all resources"
  default     = "attack-range"
}

variable "location" {
  description = "Azure region"
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group name"
  default     = "attack-range-rg"
}

variable "admin_username" {
  description = "Admin username for VMs"
  default     = "azureuser"
}

variable "admin_password" {
  description = "Admin password for VMs"
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key for Linux VMs"
  type        = string
}

variable "allowed_ip" {
  description = "IP address allowed to connect to the Attack Range"
  type        = string
  default     = "0.0.0.0/0"
}

variable "enable_premium_connectors" {
  description = "Whether to enable premium connectors that require specific licenses/permissions"
  type        = bool
  default     = false
}

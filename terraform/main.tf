# main.tf
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "law" {
  name                = "${var.prefix}-law"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# Add Microsoft Sentinel Solution
resource "azurerm_log_analytics_solution" "sentinel" {
  solution_name         = "SecurityInsights"
  location             = azurerm_resource_group.rg.location
  resource_group_name  = azurerm_resource_group.rg.name
  workspace_resource_id = azurerm_log_analytics_workspace.law.id
  workspace_name       = azurerm_log_analytics_workspace.law.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityInsights"
  }
}

# Enable Microsoft Sentinel
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}

# Data Collection rule
resource "azurerm_monitor_data_collection_rule" "dcr" {
  name                = "${var.prefix}-dcr"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  kind                = "Windows"

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
      name                 = "law"
    }
  }

  data_sources {
    windows_event_log {
      streams = ["Microsoft-Event", "Microsoft-SecurityEvent"]
      name    = "security-logs"
      x_path_queries = [
        "Security!*",
        "System!*",
        "Application!*",
	"Microsoft-Windows-Sysmon/Operational!*"
      ]
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["law"]
  }
depends_on = [azurerm_log_analytics_workspace.law, azurerm_sentinel_log_analytics_workspace_onboarding.sentinel]
}

resource "azurerm_monitor_data_collection_rule" "dcr_linux" {
  name                = "${var.prefix}-dcr-linux"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  kind                = "Linux"

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
      name                 = "law"
    }
  }

  data_sources {
    syslog {
      streams = ["Microsoft-Syslog"]
      name    = "syslog-data"
      facility_names = [
        "auth",
        "authpriv",
        "cron",
        "daemon",
        "mark",
        "kern",
        "local0",
        "local1",
        "local2",
        "local3",
        "local4",
        "local5",
        "local6",
        "local7",
        "lpr",
        "mail",
        "news",
        "syslog",
        "user",
        "uucp"
      ]
      log_levels = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]
    }
}

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["law"]
  }
}

# DCR Associations
resource "azurerm_monitor_data_collection_rule_association" "dcr_dc" {
  name                    = "dcr-dc-association"
  target_resource_id      = azurerm_windows_virtual_machine.dc.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr.id
  description            = "Association for Windows DC"
}

resource "azurerm_monitor_data_collection_rule_association" "dcr_workstation" {
  name                    = "dcr-workstation-association"
  target_resource_id      = azurerm_windows_virtual_machine.workstation.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr.id
  description            = "Association for Windows Workstation"
}

resource "azurerm_monitor_data_collection_rule_association" "dcr_win11" {
  name                    = "dcr-win11-association"
  target_resource_id      = azurerm_windows_virtual_machine.win11.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr.id
  description            = "Association for Windows 11 Workstation"
}

resource "azurerm_monitor_data_collection_rule_association" "dcr_server2025" {
  name                    = "dcr-server2025-association"
  target_resource_id      = azurerm_windows_virtual_machine.server2025.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr.id
  description            = "Association for Windows Server 2025"
}

resource "azurerm_monitor_data_collection_rule_association" "dcr_kali" {
  name                    = "dcr-kali-association"
  target_resource_id      = azurerm_linux_virtual_machine.kali.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr_linux.id
  description            = "Association for Kali Linux"
}

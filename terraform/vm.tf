# Windows DC VM
resource "azurerm_windows_virtual_machine" "dc" {
  name                = "${var.prefix}-dc"
  computer_name       = "win-dc"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v5"
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.dc_nic.id]
  
  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }
  tags = {
    "Defender-Off" = "true"
  }
}

# Windows Workstation VM
resource "azurerm_windows_virtual_machine" "workstation" {
  name                = "${var.prefix}-workstation"
  computer_name       = "win-work"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v5"
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.workstation_nic.id]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "Windows-10"
    sku       = "win10-22h2-pro"
    version   = "latest"
  }
  tags = {
    "Defender-Off" = "true"
  }
}

# Windows 11 Workstation VM
resource "azurerm_windows_virtual_machine" "win11" {
  name                = "${var.prefix}-win11"
  computer_name       = "win11"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v5"
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.win11_nic.id]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "windows-11"
    sku       = "win11-22h2-pro"
    version   = "latest"
  }
  tags = {
    "Defender-Off" = "true"
  }
}

# Windows Server 2025 VM
resource "azurerm_windows_virtual_machine" "server2025" {
  name                = "${var.prefix}-server2025"
  computer_name       = "win-srv25"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v5"
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.server2025_nic.id]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition"
    version   = "latest"
  }
  tags = {
    "Defender-Off" = "true"
  }
}

# Kali Linux VM
resource "azurerm_linux_virtual_machine" "kali" {
  name                = "${var.prefix}-kali"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D2s_v3"
  admin_username      = "kali"
  
  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = "kali"
    public_key = var.ssh_public_key
  }

  network_interface_ids = [azurerm_network_interface.kali_nic.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
  tags = {
    "Defender-Off" = "true"
  }
}

# VM Extensions

# Azure Monitor Agent Extensions
resource "azurerm_virtual_machine_extension" "ama_dc" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorWindowsAgent"
  type_handler_version      = "1.0"
  auto_upgrade_minor_version = true
}

resource "azurerm_virtual_machine_extension" "ama_workstation" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.workstation.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorWindowsAgent"
  type_handler_version      = "1.0"
  auto_upgrade_minor_version = true
}

resource "azurerm_virtual_machine_extension" "ama_win11" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.win11.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorWindowsAgent"
  type_handler_version      = "1.0"
  auto_upgrade_minor_version = true
}

resource "azurerm_virtual_machine_extension" "ama_server2025" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.server2025.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorWindowsAgent"
  type_handler_version      = "1.0"
  auto_upgrade_minor_version = true
}

resource "azurerm_virtual_machine_extension" "ama_kali" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.kali.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorLinuxAgent"
  type_handler_version      = "1.0"
  auto_upgrade_minor_version = true
}

# WinRM Extensions
resource "azurerm_virtual_machine_extension" "winrm_dc" {
  name                       = "winrm-config-dc"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc.id
  publisher                 = "Microsoft.Compute"
  type                      = "CustomScriptExtension"
  type_handler_version      = "1.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    "timestamp" : timestamp()  # Force update on each apply
  })

  protected_settings = jsonencode({
    "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ConfigureWinRM.ps1",
    "fileUris": ["https://raw.githubusercontent.com/oloruntolaallbert/public/refs/heads/main/ConfigureWinRM.ps1"]
  })

  depends_on = [
    azurerm_windows_virtual_machine.dc,
    azurerm_virtual_machine_extension.ama_dc
  ]

  timeouts {
    create = "30m"
    delete = "30m"
  }
}

resource "azurerm_virtual_machine_extension" "winrm_workstation" {
  name                       = "winrm-config-workstation"
  virtual_machine_id         = azurerm_windows_virtual_machine.workstation.id
  publisher                 = "Microsoft.Compute"
  type                      = "CustomScriptExtension"
  type_handler_version      = "1.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    "timestamp" : timestamp()  # Force update on each apply
  })

  protected_settings = jsonencode({
    "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ConfigureWinRM.ps1",
    "fileUris": ["https://raw.githubusercontent.com/oloruntolaallbert/public/refs/heads/main/ConfigureWinRM.ps1"]
  })

  depends_on = [
    azurerm_windows_virtual_machine.workstation,
    azurerm_virtual_machine_extension.ama_workstation
  ]

  timeouts {
    create = "30m"
    delete = "30m"
  }
}

resource "azurerm_virtual_machine_extension" "winrm_win11" {
  name                       = "winrm-config-win11"
  virtual_machine_id         = azurerm_windows_virtual_machine.win11.id
  publisher                 = "Microsoft.Compute"
  type                      = "CustomScriptExtension"
  type_handler_version      = "1.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    "timestamp" : timestamp()
  })

  protected_settings = jsonencode({
    "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ConfigureWinRM.ps1",
    "fileUris": ["https://raw.githubusercontent.com/oloruntolaallbert/public/refs/heads/main/ConfigureWinRM.ps1"]
  })

  depends_on = [
    azurerm_windows_virtual_machine.win11,
    azurerm_virtual_machine_extension.ama_win11
  ]

  timeouts {
    create = "30m"
    delete = "30m"
  }
}

resource "azurerm_virtual_machine_extension" "winrm_server2025" {
  name                       = "winrm-config-server2025"
  virtual_machine_id         = azurerm_windows_virtual_machine.server2025.id
  publisher                 = "Microsoft.Compute"
  type                      = "CustomScriptExtension"
  type_handler_version      = "1.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    "timestamp" : timestamp()
  })

  protected_settings = jsonencode({
    "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ConfigureWinRM.ps1",
    "fileUris": ["https://raw.githubusercontent.com/oloruntolaallbert/public/refs/heads/main/ConfigureWinRM.ps1"]
  })

  depends_on = [
    azurerm_windows_virtual_machine.server2025,
    azurerm_virtual_machine_extension.ama_server2025
  ]

  timeouts {
    create = "30m"
    delete = "30m"
  }
}

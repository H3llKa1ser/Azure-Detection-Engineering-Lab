# ---------------------------------------------------------------------------
# Victim hosts: one Windows Server, one Ubuntu. No public IPs. Both run the
# Azure Monitor Agent (AMA) and ship logs according to the DCRs in dcr.tf.
# ---------------------------------------------------------------------------

resource "random_password" "win_admin" {
  length           = 24
  special          = true
  override_special = "!#%*-_=+"
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "tls_private_key" "linux_admin" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# --- Windows ---------------------------------------------------------------

resource "azurerm_network_interface" "win" {
  count               = var.deploy_windows_vm ? 1 : 0
  name                = "nic-win-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.victims.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "win" {
  #checkov:skip=CKV_AZURE_50:VM extensions are required - the Azure Monitor Agent is the telemetry source for this lab.
  #checkov:skip=CKV_AZURE_151:Encryption at host needs a per-subscription feature registration; omitted to keep the lab one-command deployable.
  count                 = var.deploy_windows_vm ? 1 : 0
  name                  = "vm-win-${local.name}"
  computer_name         = "win-${local.suffix}"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = var.vm_size
  admin_username        = "labadmin"
  admin_password        = random_password.win_admin.result
  network_interface_ids = [azurerm_network_interface.win[0].id]

  secure_boot_enabled        = true
  vtpm_enabled               = true
  automatic_updates_enabled  = true
  patch_mode                 = "AutomaticByOS"
  allow_extension_operations = true
  tags                       = merge(local.tags, { role = "victim-windows" })

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-g2"
    version   = "latest"
  }
}

resource "azurerm_virtual_machine_extension" "win_ama" {
  count                      = var.deploy_windows_vm ? 1 : 0
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.win[0].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.tags
}

# Windows Server does not log everything we need out of the box. Apply an
# audit baseline (logon, account/group management, process creation with
# command line) so the SecurityEvent detections have something to see.
resource "azurerm_virtual_machine_run_command" "win_audit_baseline" {
  count              = var.deploy_windows_vm ? 1 : 0
  name               = "audit-baseline"
  location           = azurerm_resource_group.lab.location
  virtual_machine_id = azurerm_windows_virtual_machine.win[0].id
  tags               = local.tags

  source {
    script = <<-PS
      auditpol /set /subcategory:"Logon" /success:enable /failure:enable
      auditpol /set /subcategory:"Special Logon" /success:enable
      auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
      auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
      auditpol /set /subcategory:"Process Creation" /success:enable
      reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
      wevtutil sl Security /ms:268435456
      Write-Output "audit baseline applied"
    PS
  }

  depends_on = [azurerm_virtual_machine_extension.win_ama]
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "win" {
  count                 = var.deploy_windows_vm ? 1 : 0
  virtual_machine_id    = azurerm_windows_virtual_machine.win[0].id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone
  tags                  = local.tags

  notification_settings {
    enabled = false
  }
}

# --- Linux -----------------------------------------------------------------

resource "azurerm_network_interface" "linux" {
  count               = var.deploy_linux_vm ? 1 : 0
  name                = "nic-lnx-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.victims.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "linux" {
  #checkov:skip=CKV_AZURE_50:VM extensions are required - the Azure Monitor Agent is the telemetry source for this lab.
  count                           = var.deploy_linux_vm ? 1 : 0
  name                            = "vm-lnx-${local.name}"
  computer_name                   = "lnx-${local.suffix}"
  location                        = azurerm_resource_group.lab.location
  resource_group_name             = azurerm_resource_group.lab.name
  size                            = var.vm_size
  admin_username                  = "labadmin"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.linux[0].id]

  secure_boot_enabled        = true
  vtpm_enabled               = true
  allow_extension_operations = true
  tags                       = merge(local.tags, { role = "victim-linux" })

  admin_ssh_key {
    username   = "labadmin"
    public_key = tls_private_key.linux_admin.public_key_openssh
  }

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

resource "azurerm_virtual_machine_extension" "linux_ama" {
  count                      = var.deploy_linux_vm ? 1 : 0
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.linux[0].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.tags
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "linux" {
  count                 = var.deploy_linux_vm ? 1 : 0
  virtual_machine_id    = azurerm_linux_virtual_machine.linux[0].id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone
  tags                  = local.tags

  notification_settings {
    enabled = false
  }
}

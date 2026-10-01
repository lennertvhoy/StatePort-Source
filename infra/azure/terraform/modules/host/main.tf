# The single StatePort alpha host: Ubuntu 24.04 LTS (Gen2) VM with a
# system-assigned managed identity and a dedicated data disk.
#
# Exposure model: exactly one public IP, attached to the VM's only NIC. The
# subnet NSG (network module) allows inbound 443 only (plus optional
# operator SSH), so this IP serves the HTTPS endpoint and nothing else.

resource "azurerm_public_ip" "this" {
  name                = "${var.name_prefix}-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "this" {
  name                = "${var.name_prefix}-nic"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.this.id
  }

  tags = var.tags
}

resource "azurerm_linux_virtual_machine" "this" {
  name                = "${var.name_prefix}-vm"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [azurerm_network_interface.this.id]

  # SSH key auth only; there is no password path into this host.
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-noble"
    sku       = "24_04-lts-gen2"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {
    storage_account_uri = var.boot_diagnostics_storage_uri
  }

  # cloud-init creates the stateport-control / stateport-exec service users,
  # installs rootless Podman prerequisites, enables lingering, and mounts the
  # data disk. No secrets are passed through custom_data.
  custom_data = base64encode(templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    name_prefix       = var.name_prefix
    control_user      = var.control_user
    exec_user         = var.exec_user
    data_disk_device  = "/dev/disk/azure/scsi1/lun0"
    state_dir         = "/var/lib/stateport"
    installer_staging = "/opt/stateport"
  }))

  tags = var.tags
}

resource "azurerm_managed_disk" "data" {
  name                 = "${var.name_prefix}-data"
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = var.data_disk_size_gb
  tags                 = var.tags
}

resource "azurerm_virtual_machine_data_disk_attachment" "data" {
  managed_disk_id    = azurerm_managed_disk.data.id
  virtual_machine_id = azurerm_linux_virtual_machine.this.id
  lun                = 0
  # No host caching on the state disk: conservative durability choice for a
  # disk whose contents must survive a VM crash intact.
  caching = "None"
}

# Single VNet + single subnet for the alpha. The whole product lives on one
# VM, so there is no east-west traffic to segment; if a second host is ever
# added, subnetting is revisited then.
#
# Inbound exposure policy (deliberate, do not widen without owner approval):
#   - 443/tcp from anywhere  : the public HTTPS endpoint of the StatePort app
#   - 22/tcp  from allowed_ssh_cidrs only; with the default empty list no SSH
#     rule exists at all and the default DenyAllInbound blocks SSH entirely
#   - everything else        : denied. No public workspace/preview ports, no
#     public Podman API. Preview workspaces stay behind the host's own
#     loopback/reverse-proxy boundary on 443.

resource "azurerm_virtual_network" "this" {
  name                = "${var.name_prefix}-vnet"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = ["10.42.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "this" {
  name                 = "${var.name_prefix}-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_network_security_group" "this" {
  name                = "${var.name_prefix}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "https_inbound" {
  name                        = "Allow-HTTPS-Inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

# Created only when the operator opts in with a non-empty CIDR list.
resource "azurerm_network_security_rule" "ssh_inbound" {
  count = length(var.allowed_ssh_cidrs) > 0 ? 1 : 0

  name                        = "Allow-SSH-Inbound"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefixes     = var.allowed_ssh_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

resource "azurerm_subnet_network_security_group_association" "this" {
  subnet_id                 = azurerm_subnet.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

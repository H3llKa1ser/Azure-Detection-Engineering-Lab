# ---------------------------------------------------------------------------
# Victim network. No public IPs anywhere: hosts are driven via VM Run Command,
# which goes through the Azure control plane and the VM agent.
# ---------------------------------------------------------------------------

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.42.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "victims" {
  name                 = "snet-victims"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.42.1.0/24"]

  # The Azure Monitor Agent needs egress to the Azure Monitor ingestion
  # endpoints. Default outbound access is being retired by Microsoft; set
  # use_nat_gateway = true if your subscription/region no longer allows it.
  default_outbound_access_enabled = !var.use_nat_gateway
}

resource "azurerm_network_security_group" "victims" {
  name                = "nsg-victims-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  security_rule {
    name                       = "deny-all-internet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "victims" {
  subnet_id                 = azurerm_subnet.victims.id
  network_security_group_id = azurerm_network_security_group.victims.id
}

# Deliberately UNATTACHED NSG used only as a target for the
# "management port opened to the Internet" simulation. Editing it creates the
# exact Activity Log event the detection looks for with zero real exposure.
resource "azurerm_network_security_group" "sim" {
  name                = "nsg-sim-target-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = merge(local.tags, { purpose = "simulation-target-unattached" })
}

# Optional NAT gateway for explicit egress.
resource "azurerm_public_ip" "nat" {
  count               = var.use_nat_gateway ? 1 : 0
  name                = "pip-nat-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway" "lab" {
  count               = var.use_nat_gateway ? 1 : 0
  name                = "ng-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway_public_ip_association" "lab" {
  count                = var.use_nat_gateway ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.lab[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "victims" {
  count          = var.use_nat_gateway ? 1 : 0
  subnet_id      = azurerm_subnet.victims.id
  nat_gateway_id = azurerm_nat_gateway.lab[0].id
}

data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "rg" {
  name = var.resource_group_name
}

data "azurerm_network_security_group" "main" {
  name                = var.nsg_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_virtual_network" "main" {
  name                = var.vnet_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_subnet" "main" {
  name                 = var.subnet_name
  virtual_network_name = data.azurerm_virtual_network.main.name
  resource_group_name  = data.azurerm_resource_group.rg.name
}

data "azurerm_dns_zone" "main" {
  name                = var.dns_zone_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_key_vault" "main" {
  name                = var.key_vault_name
  resource_group_name = data.azurerm_resource_group.rg.name
}
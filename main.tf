### NETWORKING BITS
resource "azurerm_application_security_group" "vault" {
  name = "${var.base_name}-vault-appsg"

  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location

  tags = var.tags
}

## IP/interface stuff
resource "azurerm_public_ip" "vault" {
  name                = "${var.base_name}-vault-publicip01"
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = var.tags
}

resource "azurerm_network_interface" "vault" {
  name                = "${var.base_name}-vault-nic01"
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location

  ip_configuration {
    name                          = "${var.base_name}-vault-nic01"
    subnet_id                     = data.azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vault.id
  }

  tags = var.tags
}

resource "azurerm_network_interface_application_security_group_association" "vault" {
  network_interface_id          = azurerm_network_interface.vault.id
  application_security_group_id = azurerm_application_security_group.vault.id
}

## Inbound firewall
resource "azurerm_network_security_rule" "inbound_ssh" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "in-vault-ssh"

  priority                                   = 1000
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_address_prefixes                    = var.my_ip_addresses
  source_port_range                          = "*"
  destination_application_security_group_ids = [azurerm_application_security_group.vault.id]
  destination_port_range                     = "22"
}

resource "azurerm_network_security_rule" "inbound_https" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "in-vault-https"

  priority                                   = 1100
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_address_prefixes                    = var.my_ip_addresses
  source_port_range                          = "*"
  destination_application_security_group_ids = [azurerm_application_security_group.vault.id]
  destination_port_range                     = "443"
}

## Outbound firewall
resource "azurerm_network_security_rule" "outbound_azure_keyvault" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "out-vault-azure-keyvault"

  priority                              = 1000
  direction                             = "Outbound"
  access                                = "Allow"
  protocol                              = "Tcp"
  source_application_security_group_ids = [azurerm_application_security_group.vault.id]
  source_port_range                     = "*"
  destination_address_prefix            = "AzureKeyVault"
  destination_port_range                = "*"
}

resource "azurerm_network_security_rule" "outbound_azure_storage" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "out-vault-azure-storage"

  priority                              = 1005
  direction                             = "Outbound"
  access                                = "Allow"
  protocol                              = "Tcp"
  source_application_security_group_ids = [azurerm_application_security_group.vault.id]
  source_port_range                     = "*"
  destination_address_prefix            = "Storage"
  destination_port_range                = "*"
}

resource "azurerm_network_security_rule" "outbound_azure_activedirectory" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "out-vault-azure-activedirectory"

  priority                              = 1010
  direction                             = "Outbound"
  access                                = "Allow"
  protocol                              = "Tcp"
  source_application_security_group_ids = [azurerm_application_security_group.vault.id]
  source_port_range                     = "*"
  destination_address_prefix            = "AzureActiveDirectory"
  destination_port_range                = "*"
}

resource "azurerm_network_security_rule" "outbound_http_to_internet" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "out-vault-http-to-internet"

  priority                              = 1500
  direction                             = "Outbound"
  access                                = "Allow"
  protocol                              = "Tcp"
  source_application_security_group_ids = [azurerm_application_security_group.vault.id]
  source_port_range                     = "*"
  destination_address_prefix            = "Internet"
  destination_port_ranges               = ["80", "443"]
}

resource "azurerm_network_security_rule" "outbound_ntp_to_internet" {
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = data.azurerm_network_security_group.main.name

  name = "out-vault-ntp-to-internet"

  priority                              = 1510
  direction                             = "Outbound"
  access                                = "Allow"
  protocol                              = "Udp"
  source_application_security_group_ids = [azurerm_application_security_group.vault.id]
  source_port_range                     = "*"
  destination_address_prefix            = "Internet"
  destination_port_range                = "123"
}

### DNS BITS
resource "azurerm_dns_a_record" "vault" {
  name                = var.vault_hostname
  zone_name           = data.azurerm_dns_zone.main.name
  resource_group_name = data.azurerm_resource_group.rg.name
  ttl                 = 300
  records             = [azurerm_public_ip.vault.ip_address]
}

### ROLE/IAM STUFF FOR THE VAULT VM
resource "azurerm_user_assigned_identity" "vault" {
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location

  name = "${var.base_name}-vault-vm-identity"

  tags = var.tags
}

resource "azurerm_role_definition" "vault" {
  name        = "${var.base_name}-vault-role"
  scope       = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  description = "Allows Vault cluster nodes to access Key Vault and VM metadata for authentication purposes"

  assignable_scopes = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]

  permissions {
    actions = [
      # This allows other entities (e.g. VMs) with their own MSI to authenticate to Vault as clients
      "Microsoft.Compute/virtualMachines/*/read",
      "Microsoft.Compute/virtualMachineScaleSets/*/read",
      # This allows the VM to add TXT records to validate its LetsEncrypt certificate
      # It's disabled also because the script we use to manage LetsEncrypt, acme.sh, doesn't support managed system identities.
      # So there's no point in granting the VM permissions to tweak DNS records.
      # "Microsoft.Network/dnszones/read",
      # "Microsoft.Network/dnszones/TXT/read",
      # "Microsoft.Network/dnszones/TXT/write",
      # "Microsoft.Network/dnszones/TXT/delete",
    ]
    data_actions = [
      "Microsoft.KeyVault/vaults/secrets/getSecret/action",
      "Microsoft.KeyVault/vaults/secrets/setSecret/action",
      "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/keys/update/action",
      "Microsoft.KeyVault/vaults/keys/create/action",
      "Microsoft.KeyVault/vaults/keys/delete",
      "Microsoft.KeyVault/vaults/keys/wrap/action",
      "Microsoft.KeyVault/vaults/keys/unwrap/action",
    ]
  }
}

resource "azurerm_role_assignment" "vault" {
  scope              = data.azurerm_resource_group.rg.id
  role_definition_id = azurerm_role_definition.vault.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.vault.principal_id
}

### KEY VAULT BITS
# This policy allows Hashicorp Vault to access what it needs from Azure Key Vault
resource "azurerm_key_vault_access_policy" "vault_vm" {
  key_vault_id = data.azurerm_key_vault.main.id

  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azurerm_user_assigned_identity.vault.principal_id
  key_permissions    = ["create", "get", "delete", "list", "update", "wrapKey", "unwrapKey"]
  secret_permissions = ["get", "set"]

  depends_on = [azurerm_role_assignment.vault]
}

resource "azurerm_key_vault_key" "main" {
  name         = "${var.base_name}-vault-key"
  key_vault_id = data.azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]

  depends_on = [azurerm_key_vault_access_policy.vault_vm]
}

resource "azurerm_linux_virtual_machine" "main" {
  name                = "${var.base_name}-vault-vm"
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location
  size                = var.vm_size

  network_interface_ids = [azurerm_network_interface.vault.id]

  admin_username = var.vm_admin_username
  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = var.vm_admin_public_key
  }

  disable_password_authentication = true

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  os_disk {
    storage_account_type = "StandardSSD_LRS"
    caching              = "ReadWrite"
    disk_size_gb         = 32
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vault.id]
  }

  custom_data = base64encode(templatefile("${path.module}/vm_custom_data.sh.tpl", {
    gid                          = var.vault_gid
    uid                          = var.vault_uid
    vault_version                = var.vault_version
    vault_config_path            = var.vault_config_path
    vault_data_path              = var.vault_data_path
    vault_log_path               = var.vault_log_path
    vault_fqdn                   = trim(azurerm_dns_a_record.vault.fqdn, ".")
    acme_staging                 = var.acme_staging
    key_vault_name               = var.key_vault_name
    username                     = var.vm_admin_username
    azure_dns_subscription_id    = var.dns_validation_subscription_id
    azure_dns_tenant_id          = var.azure_tenant_id
    azure_dns_client_id          = var.azure_dns_client_id
    azure_dns_client_secret      = var.azure_dns_client_secret
    certificate_file             = var.certificate_file_name
    certificate_private_key_file = var.certificate_private_key_file_name

    vault_config_file = templatefile("${path.module}/vault_config.hcl.tpl", {
      vault_config_path            = var.vault_config_path
      certificate_file             = var.certificate_file_name
      certificate_private_key_file = var.certificate_private_key_file_name
      raft_data_path               = var.vault_data_path
      azure_tenant_id              = var.azure_tenant_id
      key_vault_name               = var.key_vault_name
      key_vault_key_name           = azurerm_key_vault_key.main.name
    })
  }))

  tags = var.tags
}
output "vault_public_ip" {
  value = azurerm_public_ip.vault.ip_address
}

output "vault_fqdn" {
  value = trim(azurerm_dns_a_record.vault.fqdn, ".")
}
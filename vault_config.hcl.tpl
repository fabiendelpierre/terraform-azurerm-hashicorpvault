listener "tcp" {
  address = "0.0.0.0:443"
  tls_cert_file = "${vault_config_path}/${certificate_file}"
  tls_key_file = "${vault_config_path}/${certificate_private_key_file}"
}

storage "raft" {
  path = "${raft_data_path}"
  node_id = "raft_node_1"
}

seal "azurekeyvault" {
  tenant_id = "${azure_tenant_id}"
  vault_name = "${key_vault_name}"
  key_name = "${key_vault_key_name}"
}

api_addr = "https://0.0.0.0:443"
cluster_addr = "http://127.0.0.1:8201"
disable_mlock = true
ui = true
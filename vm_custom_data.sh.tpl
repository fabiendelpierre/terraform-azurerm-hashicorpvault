#!/bin/bash

# Prepare to install packages
apt-get update

# Install Azure CLI package
apt-get install -y ca-certificates curl apt-transport-https lsb-release gnupg
curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/trusted.gpg.d/microsoft.asc.gpg > /dev/null
AZ_REPO=$(lsb_release -cs)
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | tee /etc/apt/sources.list.d/azure-cli.list
apt-get update
apt-get install -y azure-cli

# Install required system packages
apt-get install -y jq unzip

# Need to install Node.js for the self-hosted GitHub Actions runner
curl -sL https://deb.nodesource.com/setup_15.x | bash -
apt-get install -y nodejs

# Install the GitHub Actions runner
GITHUB_ACTIONS_HOME="/home/${username}/actions-runner"
mkdir -p $GITHUB_ACTIONS_HOME
cd $GITHUB_ACTIONS_HOME
curl -O -L https://github.com/actions/runner/releases/download/v2.275.1/actions-runner-linux-x64-2.275.1.tar.gz
tar xzf $GITHUB_ACTIONS_HOME/actions-runner-linux-x64-2.275.1.tar.gz
cd -

# Clean up
apt-get autoremove -y

# Set up a UNIX user and group for Vault
VAULT_CONFIG_PATH="${vault_config_path}"
VAULT_RAFT_DATA="${vault_data_path}"
mkdir -p $VAULT_CONFIG_PATH $VAULT_RAFT_DATA
groupadd --system -g ${gid} vault
useradd --system -u ${uid} -g vault --home $VAULT_CONFIG_PATH --shell /bin/false vault
chown root:${gid} $VAULT_CONFIG_PATH $VAULT_RAFT_DATA
chmod 770 $VAULT_CONFIG_PATH $VAULT_RAFT_DATA

# Install acme.sh so we can request an SSL certificate for TFE
ACME_INSTALL="/home/${username}/acme-sh-install"
ACME_HOME="/home/${username}/.acme.sh"
git clone https://github.com/acmesh-official/acme.sh.git $ACME_INSTALL
cd $ACME_INSTALL
./acme.sh --install --home $ACME_HOME
chown -R ${username}:${username} $ACME_HOME
cd $ACME_HOME
rm -rf $ACME_INSTALL

# Write to disk a script that will be run automatically after renewing the certificate
touch $ACME_HOME/hook_scripts.sh
chmod +x $ACME_HOME/hook_scripts.sh
cat << "EOF" | tee $ACME_HOME/hook_scripts.sh
#!/bin/bash

# Log in to Azure using the VM's managed identity
az login --identity

ACME_HOME="/home/${username}/.acme.sh"

# Check if cert files were modified recently
# Input file
FILE=$ACME_HOME/${vault_fqdn}/fullchain.cer
# The cert is arbitrarily considered to be old if the last modified time is more than 5 minutes ago
OLDTIME=300
# Get the current time
CURTIME=$(date +%s)
# Get the time the file was last modified
FILETIME=$(stat $FILE -c %Y)
# Get the difference between the two values
TIMEDIFF=$(expr $CURTIME - $FILETIME)

# Check if the file is older than $OLDTIME above
if [ $TIMEDIFF -gt $OLDTIME ]
then
  # If yes, then assume the cert renewal failed and exit with an error
  exit 1
else
  # If not, assume the cert was renewed successfully in the past few minutes, and upload it to Key Vault

  # Set the names of the Key Vault secrets
  SECRET_NAME_PREFIX=$(echo ${vault_fqdn} | tr "." "-")
  SECRET_CA_CERT="$SECRET_NAME_PREFIX-cert-ca"
  SECRET_FULLCHAIN_CERT="$SECRET_NAME_PREFIX-cert-fullchain"
  SECRET_CERT_FILE="$SECRET_NAME_PREFIX-cert-file"
  SECRET_CONF_FILE="$SECRET_NAME_PREFIX-cert-conf"
  SECRET_CSR_FILE="$SECRET_NAME_PREFIX-cert-csr"
  SECRET_CSR_CONF_FILE="$SECRET_NAME_PREFIX-cert-csr-conf"
  SECRET_PRIVATE_KEY="$SECRET_NAME_PREFIX-cert-private-key"

  # Store the files relating to the cert as base64 strings for ease of management
  CA_CERT=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/ca.cer)
  FULLCHAIN_CERT=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/fullchain.cer)
  CERT_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.cer)
  CONF_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.conf)
  CSR_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.csr)
  CSR_CONF_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.csr.conf)
  PRIVATE_KEY=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.key)

  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CA_CERT --encoding base64 --value $CA_CERT
  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_FULLCHAIN_CERT --encoding base64 --value $FULLCHAIN_CERT
  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CERT_FILE --encoding base64 --value $CERT_FILE
  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CONF_FILE --encoding base64 --value $CONF_FILE
  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CSR_FILE --encoding base64 --value $CSR_FILE
  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CSR_CONF_FILE --encoding base64 --value $CSR_CONF_FILE
  az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_PRIVATE_KEY --encoding base64 --value $PRIVATE_KEY

  # Now install the new cert so Vault can use it
  # Set some variables
  VAULT_CONFIG_PATH="${vault_config_path}"
  TEMP_CERT_FILE="/tmp/certificate.crt"
  TEMP_KEY_FILE="/tmp/certificate.pem"
  PERM_CERT_FILE="$VAULT_CONFIG_PATH/${certificate_file}"
  PERM_KEY_FILE="$VAULT_CONFIG_PATH/${certificate_private_key_file}"

  # Download the current certificate and private key files
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_FULLCHAIN_CERT | jq -r '.value' | base64 -d | tee $TEMP_CERT_FILE > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_PRIVATE_KEY | jq -r '.value' | base64 -d | tee $TEMP_KEY_FILE > /dev/null

  # Stop the Vault service so we can swap the old cert for the new one
  systemctl stop vault

  # Overwrite the old cert with the new one
  cp -f $TEMP_CERT_FILE $PERM_CERT_FILE
  cp -f $TEMP_KEY_FILE $PERM_KEY_FILE

  # Make sure the permissions on the cert files are good
  chown root:vault $PERM_CERT_FILE $PERM_KEY_FILE
  chmod 640 $PERM_CERT_FILE $PERM_KEY_FILE

  # Restart Vault now that our work is done
  systemctl start vault

  # Clean up the temp files
  rm -f $TEMP_CERT_FILE $TEMP_KEY_FILE
fi
EOF

# Log in to Azure using the VM's managed identity
az login --identity

# Set some env variables for acme.sh
export AZUREDNS_SUBSCRIPTIONID="${azure_dns_subscription_id}"
export AZUREDNS_TENANTID="${azure_dns_tenant_id}"
export AZUREDNS_APPID="${azure_dns_client_id}"
export AZUREDNS_CLIENTSECRET="${azure_dns_client_secret}"

# Reusable function to check if a secret exists in Azure Key Vault
secret_exists () {
  local vault_name=$1
  local secret_name=$2
  if az keyvault secret show --vault-name $1 --name $2 2>&1 | grep file-encoding >/dev/null
  then
    retval=0
  else
    retval=1
  fi
  return "$retval"
}

# Set the names of the Key Vault secrets
SECRET_NAME_PREFIX=$(echo ${vault_fqdn} | tr "." "-")
SECRET_CA_CERT="$SECRET_NAME_PREFIX-cert-ca"
SECRET_FULLCHAIN_CERT="$SECRET_NAME_PREFIX-cert-fullchain"
SECRET_CERT_FILE="$SECRET_NAME_PREFIX-cert-file"
SECRET_CONF_FILE="$SECRET_NAME_PREFIX-cert-conf"
SECRET_CSR_FILE="$SECRET_NAME_PREFIX-cert-csr"
SECRET_CSR_CONF_FILE="$SECRET_NAME_PREFIX-cert-csr-conf"
SECRET_PRIVATE_KEY="$SECRET_NAME_PREFIX-cert-private-key"

# This checks if the full chain cert created by acme.sh already exists in Key Vault
# If yes, we attempt to pull the cert files from Key Vault.
# If not, we request a new cert from LetsEncrypt using acme.sh.
if secret_exists "${key_vault_name}" "$SECRET_FULLCHAIN_CERT" == 0
then
  echo "Found existing certificate for ${vault_fqdn} in Key Vault ${key_vault_name}, don't generate a new one."
  # Create the path where acme.sh expects cert files
  mkdir -p $ACME_HOME/${vault_fqdn}

  # acme.sh produces a bunch of files, gotta catch 'em all!
  echo "Downloading cert data from Key Vault..."
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_CA_CERT | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/ca.cer > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_FULLCHAIN_CERT | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/fullchain.cer > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_CERT_FILE | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/${vault_fqdn}.cer > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_CONF_FILE | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/${vault_fqdn}.conf > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_CSR_FILE | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/${vault_fqdn}.csr > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_CSR_CONF_FILE | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/${vault_fqdn}.csr.conf > /dev/null
  az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_PRIVATE_KEY | jq -r .value | base64 -d | tee $ACME_HOME/${vault_fqdn}/${vault_fqdn}.key > /dev/null
  echo "Pulled existing certificate data from Key Vault." | tee /home/ubuntu/cert_status

  # This will add the Azure tenant/subscription/API creds to the acme.sh config file
  echo "Setting up acme.sh for future renewals..."
  echo "SAVED_AZUREDNS_SUBSCRIPTIONID=$AZUREDNS_SUBSCRIPTIONID" | tee -a $ACME_HOME/account.conf > /dev/null
  echo "SAVED_AZUREDNS_TENANTID=$AZUREDNS_TENANTID" | tee -a $ACME_HOME/account.conf > /dev/null
  echo "SAVED_AZUREDNS_APPID=$AZUREDNS_APPID" | tee -a $ACME_HOME/account.conf > /dev/null
  echo "SAVED_AZUREDNS_CLIENTSECRET=$AZUREDNS_CLIENTSECRET" | tee -a $ACME_HOME/account.conf > /dev/null

  echo "Finished setting up acme.sh."
else
  echo "Secret $SECRET_FULLCHAIN_CERT not found in Key Vault ${key_vault_name}, request a new cert from LetsEncrypt..."
  # Request a cert
  # Check whether Terraform was run with var.vm_certs_acme_staging = true or false
  # This controls whether we talk to LetsEncrypt's staging or prod endpoint
  if "${acme_staging}" == "true"
  then
    ACME_STAGING=" --staging"
  fi
  cd $ACME_HOME
  ./acme.sh$ACME_STAGING --home $ACME_HOME --issue --dns dns_azure -d ${vault_fqdn} --renew-hook $ACME_HOME/hook_scripts.sh
  cd -

  if [[ -f $ACME_HOME/${vault_fqdn}/fullchain.cer ]]
  then
    echo "The certificate was issued successfully, uploading it to Key Vault..."

    Store the files relating to the cert as base64 strings for ease of management
    CA_CERT=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/ca.cer)
    FULLCHAIN_CERT=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/fullchain.cer)
    CERT_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.cer)
    CONF_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.conf)
    CSR_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.csr)
    CSR_CONF_FILE=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.csr.conf)
    PRIVATE_KEY=$(base64 -w 0 $ACME_HOME/${vault_fqdn}/${vault_fqdn}.key)

    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CA_CERT --encoding base64 --value $CA_CERT
    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_FULLCHAIN_CERT --encoding base64 --value $FULLCHAIN_CERT
    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CERT_FILE --encoding base64 --value $CERT_FILE
    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CONF_FILE --encoding base64 --value $CONF_FILE
    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CSR_FILE --encoding base64 --value $CSR_FILE
    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_CSR_CONF_FILE --encoding base64 --value $CSR_CONF_FILE
    az keyvault secret set --vault-name ${key_vault_name} --name $SECRET_PRIVATE_KEY --encoding base64 --value $PRIVATE_KEY

    echo "A new cert was generated and uploaded to Key Vault." | tee /home/ubuntu/cert_status
  fi
fi

# Grab the SSL certificate and private key from Key Vault
SECRET_NAME_PREFIX=$(echo ${vault_fqdn} | tr "." "-")
SECRET_FULLCHAIN_CERT="$SECRET_NAME_PREFIX-cert-fullchain"
SECRET_PRIVATE_KEY="$SECRET_NAME_PREFIX-cert-private-key"
az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_FULLCHAIN_CERT | jq -r '.value' | base64 -d | tee $VAULT_CONFIG_PATH/${certificate_file} > /dev/null
az keyvault secret show --vault-name ${key_vault_name} --name $SECRET_PRIVATE_KEY | jq -r '.value' | base64 -d | tee $VAULT_CONFIG_PATH/${certificate_private_key_file} > /dev/null
chown root:vault $VAULT_CONFIG_PATH/*
chmod 640 $VAULT_CONFIG_PATH/*

# Write Vault config file
VAULT_CONFIG_FILE="$VAULT_CONFIG_PATH/vault.hcl"
cat << EOF | tee $VAULT_CONFIG_FILE
${vault_config_file}
EOF
chown root:vault $VAULT_CONFIG_FILE
chmod 640 $VAULT_CONFIG_FILE

# Create the path where the Vault audit log will live and set its permissions
AUDIT_LOG_PATH="${vault_log_path}"
mkdir -p $AUDIT_LOG_PATH
chown vault:vault $AUDIT_LOG_PATH
chmod 750 $AUDIT_LOG_PATH

# Download Vault
VAULT_DOWNLOAD_BASE_URL="https://releases.hashicorp.com/vault"
VAULT_CHECKSUM=$(curl -s $VAULT_DOWNLOAD_BASE_URL/${vault_version}/vault_${vault_version}_SHA256SUMS | grep linux_amd64 | awk '{print $1}')
curl --silent --remote-name $VAULT_DOWNLOAD_BASE_URL/${vault_version}/vault_${vault_version}_linux_amd64.zip

# Verify Vault archive checksum from earlier
file_checksum=$(sha256sum vault_${vault_version}_linux_amd64.zip | awk '{print $1}')

if [[ ! "$VAULT_CHECKSUM" == "$file_checksum" ]]
then
  echo Checksum mismatch, aborting...
  exit 1
fi

# Install Vault binary
VAULT_INSTALL_PATH="/usr/local/bin"
unzip vault_${vault_version}_linux_amd64.zip
mv vault $VAULT_INSTALL_PATH/
chown root:root $VAULT_INSTALL_PATH/vault
chmod 755 $VAULT_INSTALL_PATH/vault
$VAULT_INSTALL_PATH/vault --version
# Clean up
rm -f vault_${vault_version}*zip

# Set up Vault
# CLI autocomplete
$VAULT_INSTALL_PATH/vault -autocomplete-install
complete -C $VAULT_INSTALL_PATH/vault vault

# HashiCorp says to do this for security reasons
setcap 'cap_ipc_lock=+ep' $VAULT_INSTALL_PATH/vault

# Do this to allow Vault to bind to port 443
setcap CAP_NET_BIND_SERVICE=+eip $VAULT_INSTALL_PATH/vault

# Set up Vault systemd unit
touch /etc/systemd/system/vault.service
cat << EOF | tee /etc/systemd/system/vault.service
[Unit]
Description="HashiCorp Vault - A tool for managing secrets"
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=$VAULT_CONFIG_FILE
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=$VAULT_CONFIG_FILE
EOF
cat << "EOF" | tee -a /etc/systemd/system/vault.service
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Set VAULT_ADDR env variable for all users
echo export VAULT_ADDR="https://localhost" > /etc/profile.d/vault.sh
echo export VAULT_SKIP_VERIFY=true >> /etc/profile.d/vault.sh
export VAULT_ADDR="https://localhost"
export VAULT_SKIP_VERIFY=true

# Start Vault
systemctl enable vault
systemctl start vault

# Wait a little bit for Vault to come up before moving on
sleep 20s

# Initialize Vault if needed
# Check if Vault is already initialized
INITCHECK=$($VAULT_INSTALL_PATH/vault status -format=json | jq .initialized)
# This is where we'll put the recovery keys if the Vault is not already initialized
KEYS_FILE="/tmp/keys"

# If Vault is not initialized, then do that, and record the recovery keys and root token in a text file
if [[ "$INITCHECK" == "false" ]]
then
  $VAULT_INSTALL_PATH/vault operator init > $KEYS_FILE
  # Parse the text file with the recovery keys.
  # Get the keys from the text file and put them in environment variables.
  RECOVERY_KEY_1=$(grep "Recovery Key 1" $KEYS_FILE | cut -d':' -f2 | tr -d ' ')
  RECOVERY_KEY_2=$(grep "Recovery Key 2" $KEYS_FILE | cut -d':' -f2 | tr -d ' ')
  RECOVERY_KEY_3=$(grep "Recovery Key 3" $KEYS_FILE | cut -d':' -f2 | tr -d ' ')
  RECOVERY_KEY_4=$(grep "Recovery Key 4" $KEYS_FILE | cut -d':' -f2 | tr -d ' ')
  RECOVERY_KEY_5=$(grep "Recovery Key 5" $KEYS_FILE | cut -d':' -f2 | tr -d ' ')
  # Also get the root token from the text file
  INITIAL_ROOT_TOKEN=$(grep "Initial Root Token" $KEYS_FILE | cut -d':' -f2 | tr -d ' ')

  # Delete the text file with the plain text secrets, now that its values have been stored in variables
  rm -f $KEYS_FILE

  # Even though this code should run only if Vault is NOT already initialized,
  # let's be careful and check if secrets already exist before writing them to
  # Key Vault. We don't want to overwrite anything accidentally.

  SECRET_NAME_PREFIX=$(echo ${vault_fqdn} | tr "." "-")

  # Recovery key 1
  if secret_exists "${key_vault_name}" "$SECRET_NAME_PREFIX-recovery-key-1" == 0
  then
    # If yes, do nothing
    echo Secret $SECRET_NAME_PREFIX-recovery-key-1 already exists, skipping Key Vault upload step...
  else
    # If not, write the secret to Key Vault
    az keyvault secret set --name $SECRET_NAME_PREFIX-recovery-key-1 --vault-name ${key_vault_name} --value "$RECOVERY_KEY_1"
  fi

  # Repeat for the other unseal keys
  # Recovery key 2
  if secret_exists "${key_vault_name}" "$SECRET_NAME_PREFIX-recovery-key-2" == 0
  then
    echo Secret $SECRET_NAME_PREFIX-recovery-key-2 already exists, skipping Key Vault upload step...
  else
    az keyvault secret set --name $SECRET_NAME_PREFIX-recovery-key-2 --vault-name ${key_vault_name} --value "$RECOVERY_KEY_2"
  fi

  # Recovery key 3
  if secret_exists "${key_vault_name}" "$SECRET_NAME_PREFIX-recovery-key-3" == 0
  then
    echo Secret $SECRET_NAME_PREFIX-recovery-key-3 already exists, skipping Key Vault upload step...
  else
    az keyvault secret set --name $SECRET_NAME_PREFIX-recovery-key-3 --vault-name ${key_vault_name} --value "$RECOVERY_KEY_3"
  fi

  # Recovery key 4
  if secret_exists "${key_vault_name}" "$SECRET_NAME_PREFIX-recovery-key-4" == 0
  then
    echo Secret $SECRET_NAME_PREFIX-recovery-key-4 already exists, skipping Key Vault upload step...
  else
    az keyvault secret set --name $SECRET_NAME_PREFIX-recovery-key-4 --vault-name ${key_vault_name} --value "$RECOVERY_KEY_4"
  fi

  # Recovery key 5
  if secret_exists "${key_vault_name}" "$SECRET_NAME_PREFIX-recovery-key-5" == 0
  then
    echo Secret $SECRET_NAME_PREFIX-recovery-key-5 already exists, skipping Key Vault upload step...
  else
    az keyvault secret set --name $SECRET_NAME_PREFIX-recovery-key-5 --vault-name ${key_vault_name} --value "$RECOVERY_KEY_5"
  fi

  # Now do the same for the initial root token
  if secret_exists "${key_vault_name}" "$SECRET_NAME_PREFIX-initial-root-token" == 0
  then
    echo Secret $SECRET_NAME_PREFIX-initial-root-token already exists, skipping Key Vault upload step...
  else
    az keyvault secret set --name $SECRET_NAME_PREFIX-initial-root-token --vault-name ${key_vault_name} --value "$INITIAL_ROOT_TOKEN"
  fi
fi

# This should stay at the end
echo "This file appears in /home/${username} to tell you when the VM custom data script is done running. It does NOT mean that the script ran without issues!" | tee /home/${username}/finished
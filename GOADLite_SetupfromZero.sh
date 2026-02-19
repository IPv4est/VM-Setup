#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: FULL BUILD & ACCESS (2026)         "
echo "-------------------------------------------------------"

# 1. CLEAN START
cd "$HOME"
rm -rf GOAD_FINAL_ACCESS 2>/dev/null
mkdir GOAD_FINAL_ACCESS && cd GOAD_FINAL_ACCESS

# 2. CLONE & INSTALL
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .
python3 -m pip install ansible-core pywinrm --user --quiet
ansible-galaxy install -r ./ansible/requirements.yml 2>/dev/null

# 3. VERIFIED JUMPBOX OVERWRITE
JB_TEMPLATE=$(find . -name "jumpbox.tf" | head -n 1)
cat <<EOF > "$JB_TEMPLATE"
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "ssh_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = "\${path.root}/../ssh_keys/ubuntu-jumpbox.pem"
  file_permission = "0600"
}

resource "azurerm_public_ip" "ubuntu_public_ip" {
  name                = "ubuntu-public-ip"
  location            = azurerm_resource_group.resource_group.location
  resource_group_name = azurerm_resource_group.resource_group.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "ubuntu_jumbox_nic" {
  name                = "ubuntu-jumbox-nic"
  location            = azurerm_resource_group.resource_group.location
  resource_group_name = azurerm_resource_group.resource_group.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.ubuntu_public_ip.id
  }
}

resource "azurerm_linux_virtual_machine" "jumpbox" {
  name                = "jumpbox"
  resource_group_name = azurerm_resource_group.resource_group.name
  location            = azurerm_resource_group.resource_group.location
  size                = "Standard_D2s_v3"
  admin_username      = "goad"
  network_interface_ids = [azurerm_network_interface.ubuntu_jumbox_nic.id]
  admin_ssh_key {
    username   = "goad"
    public_key = tls_private_key.ssh.public_key_openssh
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
EOF

# 4. GLOBAL PATCHING
find . -type f -name "*.tf" -not -name "jumpbox.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g' {} +
find . -name "variables.yml" -exec perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g' {} +

# 5. LAUNCH DEPLOYMENT
echo "[*] Launching GOAD... This takes 30-60 minutes."
export TF_VAR_location="westus2"
chmod +x goad.sh
./goad.sh -t install -l GOAD-Light -p azure -m local

# 6. GENERATE ACCESS REPORT (Now at Root level)
echo "[*] Deployment finished. Generating Access Guide..."

# Locate the active workspace to pull the Public IP
WS_PATH=$(find ./workspace -type d -name "provider" | head -n 1)
JUMPBOX_IP=$(cd "$WS_PATH" && terraform output -raw public_ip_jumpbox 2>/dev/null)
SSH_KEY_PATH="$(pwd)/ssh_keys/ubuntu-jumpbox.pem"

# Fix SSH Key permissions (Critical for Mac)
chmod 400 "$SSH_KEY_PATH"

REPORT="./ACCESS_GUIDE.txt"

{
  echo "====================================================="
  echo "         GOAD-LIGHT AZURE ACCESS GUIDE               "
  echo "          Generated on: $(date)                      "
  echo "====================================================="
  echo ""
  echo "--- 1. CONNECTION DETAILS ---"
  echo "Jumpbox Public IP: $JUMPBOX_IP"
  echo "Admin Username:    goad"
  echo "SSH Key Path:      $SSH_KEY_PATH"
  echo ""
  echo "--- 2. SSH COMMAND ---"
  echo "ssh -i $SSH_KEY_PATH goad@$JUMPBOX_IP"
  echo ""
  echo "--- 3. LAB CREDENTIALS (Standard GOAD) ---"
  echo "Domain:            north.sevenkingdoms.local"
  echo "Domain Admin:      sevenkingdoms.local\administrator"
  echo "Password:          Password123!"
  echo ""
  echo "--- 4. ACTIVE DIRECTORY SERVERS ---"
  echo "DC01:  192.168.10.10 (KingsLanding)"
  echo "DC02:  192.168.10.11 (Winterfell)"
  echo "DC03:  192.168.10.12 (CastleBlack)"
  echo ""
  echo "--- 5. CLEANUP ---"
  echo "To delete everything: ./goad.sh -t terminate -l GOAD-Light -p azure"
  echo "====================================================="
} > "$REPORT"

echo "[+] Success! The guide is ready: $(pwd)/ACCESS_GUIDE.txt"
cat "$REPORT"

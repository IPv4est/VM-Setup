#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: VERIFIED DEPLOYMENT (2026)         "
echo "-------------------------------------------------------"

# 1. CLEAN START
cd "$HOME"
rm -rf GOAD_VERIFIED 2>/dev/null
mkdir GOAD_VERIFIED && cd GOAD_VERIFIED

# 2. CLONE & INSTALL
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .
python3 -m pip install ansible-core pywinrm --user --quiet
ansible-galaxy install -r ./ansible/requirements.yml 2>/dev/null

# 3. LOCATE THE TARGET
# We find the jumpbox template in the provider folder
JB_TEMPLATE=$(find . -name "jumpbox.tf" | head -n 1)

if [ -z "$JB_TEMPLATE" ]; then
    echo "[-] Error: jumpbox.tf not found in templates."
    exit 1
fi

# 4. REPLACE CONTENTS
echo "[*] Replacing contents of $JB_TEMPLATE..."

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

# 5. THE INTEGRITY CHECK
echo "[*] Verifying file integrity..."

# Check 1: Ensure no semicolons exist
if grep -q ";" "$JB_TEMPLATE"; then
    echo "[-] CRITICAL FAILURE: Semicolons detected in $JB_TEMPLATE after replacement."
    grep ";" "$JB_TEMPLATE"
    exit 1
fi

# Check 2: Ensure the file isn't empty
if [ ! -s "$JB_TEMPLATE" ]; then
    echo "[-] CRITICAL FAILURE: $JB_TEMPLATE is empty."
    exit 1
fi

echo "[+] Integrity Check Passed. File is clean."

# 6. PATCH REMAINING TEMPLATES (Global Fixes)
echo "[*] Patching remaining templates for Azure 2026..."
find . -type f -name "*.tf" -not -name "jumpbox.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g' {} +

# 7. LAUNCH
echo "[*] Launching GOAD..."
export TF_VAR_location="westus2"
chmod +x goad.sh
./goad.sh -t install -l GOAD-Light -p azure -m local

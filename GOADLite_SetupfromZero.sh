#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: THE DEFINITIVE ZERO-TO-HERO       "
echo "  Repo: IPV4est/VM-Setup (2026 Version)                "
echo "-------------------------------------------------------"

# 1. SETUP PATHS
BASE_DIR=$(pwd)
GOAD_ROOT="$BASE_DIR/GOAD"

# 2. SYSTEM CHECK
echo "[*] Checking system dependencies..."
for tool in az terraform python3 jq git; do
    if ! command -v $tool &> /dev/null; then
        echo "[*] Installing $tool via Homebrew..."
        brew install $tool
    fi
done

# 3. AZURE AUTHENTICATION
if ! az account show --output none 2>/dev/null; then
    echo "[*] Please login to Azure in the browser window..."
    az login --output table
fi

# 4. THE CLEAN CLONE
echo "[*] Cleaning up any old attempts..."
rm -rf "$GOAD_ROOT"

echo "[*] Cloning official GOAD repository..."
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git "$GOAD_ROOT"

# 5. THE CRITICAL NAVIGATION (The fix for your file error)
cd "$GOAD_ROOT" || exit 1

# Check if we are in the 'main' repo or if we need to step into the lab folder
if [ ! -f "requirements.txt" ]; then
    echo "[!] requirements.txt not in root. Searching..."
    # Some versions of GOAD put the lab files in the root, others in a subfolder.
    # We find where requirements.txt lives and move THERE.
    REAL_ROOT=$(find . -name "requirements.txt" -not -path "*/.*" | head -n 1 | xargs dirname)
    cd "$REAL_ROOT" || exit 1
    GOAD_ROOT=$(pwd)
fi

echo "[+] Successfully located Lab Root at: $GOAD_ROOT"

# 6. INSTALL REQUIREMENTS
echo "[*] Installing Ansible & Python requirements..."
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --user --quiet
ansible-galaxy role install -r requirements.yml
ansible-galaxy collection install -r requirements.yml

# 7. THE AUTOMATED PATCHES
echo "[*] Applying Azure 2026 Compatibility Patches..."
AZ_PATH="$GOAD_ROOT/template/provider/azure"
DATA_PATH="$GOAD_ROOT/ad/GOAD-Light/data"

# Region and SKU Fixes
find "$AZ_PATH" -type f -print0 | xargs -0 perl -pi -e 's/westeurope|europe/westus2/g'
find "$AZ_PATH" -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/sku\s*=\s*"Basic"/sku = "Standard"/g; s/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g'
find "$AZ_PATH" -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/Standard_B2s/Standard_D2s_v3/g'

# Network Adapter Wildcard Fix
find "$DATA_PATH" -type f -name "variables.yml" -print0 | xargs -0 perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g'

# Firewall Rule Injection
if ! grep -q "allow_mgmt" "$AZ_PATH/network.tf"; then
cat <<EOF >> "$AZ_PATH/network.tf"
resource "azurerm_network_security_rule" "allow_mgmt" {
  name                        = "allow_mgmt"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["5985", "5986", "3389"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.resource_group.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}
EOF
fi

# Jumpbox Logic (Force SSH Key Generation)
cat <<EOF > "$AZ_PATH/jumpbox.tf"
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

# 8. LAUNCH
echo "[*] Workspace cleared. Launching deployment..."
rm -rf "$GOAD_ROOT/workspace"
mkdir -p "$GOAD_ROOT/workspace"
export TF_VAR_location="westus2"
./goad.sh -t install -l GOAD-Light -p azure -m local

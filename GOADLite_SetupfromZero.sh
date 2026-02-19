#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: ZERO-TO-HERO (PATH-HARDENED)       "
echo "  Repo: IPV4est/VM-Setup                               "
echo "-------------------------------------------------------"

# 1. SYSTEM CHECK
echo "[*] Checking system dependencies..."
if ! command -v brew &> /dev/null; then
    echo "[!] Homebrew not found. Install it at https://brew.sh/"
    exit 1
fi

for tool in az terraform python3 jq; do
    if ! command -v $tool &> /dev/null; then
        echo "[*] Installing $tool..."
        brew install $tool
    fi
done

# 2. AZURE AUTHENTICATION
echo "[*] Checking Azure connection..."
if ! az account show --output none 2>/dev/null; then
    echo "[*] Opening browser for Azure Login..."
    az login --output table
fi

# 3. CLEAN CLONE (Forces the correct directory context)
if [ -d "GOAD" ]; then
    echo "[!] Existing GOAD directory found. Removing to ensure clean context..."
    rm -rf GOAD
fi

echo "[*] Cloning fresh GOAD repository..."
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD || { echo "[-] Failed to enter GOAD directory"; exit 1; }

# 4. INSTALL REQUIREMENTS
echo "[*] Installing Ansible & Python requirements..."
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt --quiet
    # Fixed galaxy syntax (No --quiet at the end)
    ansible-galaxy role install -r requirements.yml
    ansible-galaxy collection install -r requirements.yml
else
    echo "[-] ERROR: requirements.txt not found. Clone failed."
    exit 1
fi

# 5. THE AUTOMATED PATCHES (With Path Verification)
echo "[*] Applying Azure 2026 Compatibility Patches..."

# Verify the path exists before running find
AZ_PATH="template/provider/azure"
if [ ! -d "$AZ_PATH" ]; then
    echo "[-] ERROR: $AZ_PATH not found. We are in: $(pwd)"
    exit 1
fi

find "$AZ_PATH" -type f -print0 | xargs -0 perl -pi -e 's/westeurope|europe/westus2/g'
find "$AZ_PATH" -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/sku\s*=\s*"Basic"/sku = "Standard"/g; s/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g'
find "$AZ_PATH" -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/Standard_B2s/Standard_D2s_v3/g'
find ad/GOAD-Light/data -type f -name "variables.yml" -print0 | xargs -0 perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g'

# Network Security Group Logic
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

# Jumpbox Logic
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

# 6. EXECUTE
echo "[*] Cleaning workspace and launching..."
rm -rf workspace/*
export TF_VAR_location="westus2"
./goad.sh -t install -l GOAD-Light -p azure -m local

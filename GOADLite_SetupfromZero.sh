#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: ZERO-MANUAL-EDIT DEPLOYER (2026)   "
echo "-------------------------------------------------------"

# 1. SYSTEM CHECK (The "Do I have the tools?" part)
echo "[*] Ensuring you have the right tools installed..."
if ! command -v brew &> /dev/null; then
    echo "[!] Homebrew is missing. Install it at https://brew.sh/ first."
    exit 1
fi

for tool in az terraform python3 jq; do
    if ! command -v $tool &> /dev/null; then
        echo "[*] Installing $tool via Homebrew..."
        brew install $tool
    else
        echo "[+] $tool is ready."
    fi
done

# 2. AZURE LOGIN (The "UI" part)
echo "[*] Checking Azure connection..."
if ! az account show --output none 2>/dev/null; then
    echo "[*] Opening browser for Azure Login. Please select your account..."
    az login --output table
fi

# 3. GET THE LAB
if [ ! -d "GOAD" ]; then
    echo "[*] Downloading GOAD from GitHub..."
    git clone https://github.com/Orange-Cyberdefense/GOAD.git
fi
cd GOAD

# 4. INSTALL REQUIREMENTS
echo "[*] Setting up Ansible and Python dependencies..."
python3 -m pip install -r requirements.txt --quiet
ansible-galaxy install -r requirements.yml --quiet

# 5. THE AUTOMATED FIXES (THIS REPLACES ALL NANO STEPS)
echo "[*] Patching templates automatically..."

# Fix regions and IP SKUs globally (Surgical search and replace)
find template/provider/azure -type f -print0 | xargs -0 perl -pi -e 's/westeurope|europe/westus2/g'
find template/provider/azure -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/sku\s*=\s*"Basic"/sku = "Standard"/g; s/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g'
find template/provider/azure -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/Standard_B2s/Standard_D2s_v3/g'

# Add WinRM/RDP firewall rules to network.tf (The "No-Nano" way)
if ! grep -q "allow_mgmt" template/provider/azure/network.tf; then
cat <<EOF >> template/provider/azure/network.tf
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

# Create a clean Jumpbox.tf with the correct SSH logic (The "No-Nano" way)
cat <<EOF > template/provider/azure/jumpbox.tf
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

# 6. RUN
echo "[*] Cleaning workspace and launching build..."
rm -rf workspace/*
export TF_VAR_location="westus2"
./goad.sh -t install -l GOAD-Light -p azure -m local

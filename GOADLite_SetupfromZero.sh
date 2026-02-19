#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure Zero-to-Hero Bootstrapper (2026)    "
echo "-------------------------------------------------------"

# 1. PREREQUISITE CHECK & INSTALL (macOS/Homebrew focus)
echo "[*] Checking system dependencies..."

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "[!] Homebrew not found. Please install it from https://brew.sh/ and run again."
    exit 1
fi

# Function to check and install brew packages
check_and_install() {
    if ! command -v $1 &> /dev/null; then
        echo "[*] $1 not found. Installing via Homebrew..."
        brew install $1
    else
        echo "[+] $1 is already installed."
    fi
}

check_and_install "az"         # Azure CLI
check_and_install "terraform"  # Terraform
check_and_install "python3"    # Python
check_and_install "jq"         # JSON Processor (for parsing outputs)

# 2. SMART AZURE AUTHENTICATION
echo "[*] Checking Azure Authentication..."
az account show --output none 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[!] No active Azure session found. Opening browser..."
    az login --output table
else
    echo "[+] Active session detected for: $(az account show --query 'name' -o tsv)"
fi

# 3. DOWNLOAD GOAD TOOLS
if [ ! -d "GOAD" ]; then
    echo "[*] Cloning GOAD repository..."
    git clone https://github.com/Orange-Cyberdefense/GOAD.git
    cd GOAD
else
    echo "[+] GOAD directory already exists. Moving into it..."
    cd GOAD
fi

# 4. INSTALL ANSIBLE & PYTHON LIBS
echo "[*] Ensuring Python dependencies and Ansible collections are ready..."
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --quiet
ansible-galaxy install -r requirements.yml --quiet

# 5. CLEAN PREVIOUS WORKSPACE
echo "[*] Cleaning up any previous workspace data..."
rm -rf workspace/*

# 6. GLOBAL TEMPLATE FIXES (2026 Patches)
echo "[*] Applying Azure compatibility patches..."
# Set Region to West US 2
find template/provider/azure -type f -print0 | xargs -0 perl -pi -e 's/westeurope|europe/westus2/g'
# Fix IP SKU & Allocation
find template/provider/azure -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/sku\s*=\s*"Basic"/sku = "Standard"/g; s/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g'
# Fix VM Sizes
find template/provider/azure -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/Standard_B2s/Standard_D2s_v3/g'

# 7. NETWORK SECURITY GROUP PATCH (WinRM & RDP)
echo "[*] Injecting Firewall rules..."
cat <<EOF >> template/provider/azure/network.tf

resource "azurerm_network_security_rule" "allow_winrm_mgmt" {
  name                        = "allow_winrm"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["5985", "5986"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.resource_group.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

resource "azurerm_network_security_rule" "allow_rdp" {
  name                        = "allow_rdp"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["3389"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.resource_group.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}
EOF

# 8. JUMPBOX OVERWRITE (Key Logic & User Fix)
echo "[*] Finalizing Jumpbox template..."
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

# 9. LAUNCH DEPLOYMENT
echo "[*] Launching GOAD-Light..."
export TF_VAR_location="westus2"
export TF_VAR_vm_size="Standard_D2s_v3"

./goad.sh -t install -l GOAD-Light -p azure -m local

# 10. FINAL SUMMARY
echo "-------------------------------------------------------"
echo "🎉 DEPLOYMENT FINISHED!"
echo "-------------------------------------------------------"
echo "🔑 DEFAULT CREDENTIALS:"
echo "Domain:         north.sevenkingdoms.local"
echo "Admin User:     administrator"
echo "Admin Pass:     A-Very-Complex-Password-123!"
echo ""
echo "🛑 TO STOP BILLING:"
echo "./goad.sh -t terminate -l GOAD-Light -p azure"
echo "-------------------------------------------------------"

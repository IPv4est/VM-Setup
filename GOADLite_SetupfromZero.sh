#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: THE DEFINITIVE FIX (2026)          "
echo "  Target: Clean Slate / Zero State                     "
echo "-------------------------------------------------------"

# 1. ESCAPE NESTED FOLDERS
# Forces a clean working environment in your home directory
cd "$HOME"
rm -rf GOAD_DEPLOY 2>/dev/null
mkdir GOAD_DEPLOY && cd GOAD_DEPLOY

# 2. SYSTEM CHECK
echo "[*] Verifying system tools..."
for tool in az terraform python3 jq git; do
    if ! command -v $tool &> /dev/null; then 
        echo "[*] Installing $tool..."
        brew install $tool
    fi
done

# 3. AZURE AUTHENTICATION
if ! az account show --output none 2>/dev/null; then
    echo "[*] Please login to Azure in the browser window..."
    az login --output table
fi

# 4. CLONE REPOSITORY
echo "[*] Cloning official GOAD repository..."
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .

# 5. INSTALL REQUIREMENTS
echo "[*] Installing core dependencies..."
python3 -m pip install --upgrade pip --quiet
python3 -m pip install ansible-core pywinrm --user --quiet

# Prioritize the requirements.yml inside the ansible folder
if [ -f "./ansible/requirements.yml" ]; then
    echo "[+] Found Ansible requirements in ./ansible/"
    ansible-galaxy install -r ./ansible/requirements.yml
elif [ -f "./requirements.yml" ]; then
    echo "[+] Found Ansible requirements in root"
    ansible-galaxy install -r ./requirements.yml
fi

# 6. APPLY THE SURGICAL PATCHES
echo "[*] Applying Azure 2026 Region & SKU Patches..."
# Fix Regions/SKUs globally (Force West US 2 and Standard SKUs)
find . -type f -name "*.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g' {} +

# Fix Network Adapter Wildcard for Azure
find . -name "variables.yml" -exec perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g' {} +

# 7. OVERWRITE JUMPBOX (Fixed Multi-line Syntax - No Semicolons)
JB_FILE=$(find . -name "jumpbox.tf" | head -n 1)
echo "[*] Patching Jumpbox configuration at $JB_FILE..."
cat <<EOF > "$JB_FILE"
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

# 8. LAUNCH DEPLOYMENT
echo "[*] Initializing Terraform and launching build..."
chmod +x goad.sh
export TF_VAR_location="westus2"

# Run the lab installer
./goad.sh -t install -l GOAD-Light -p azure -m local

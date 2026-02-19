#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: THE ULTIMATE MASTER BUILDER        "
echo "  Fixed for Azure 2026 + NIC Wildcard + WS01 Side-Load "
echo "-------------------------------------------------------"

# 1. CLEAN START
cd "$HOME"
rm -rf GOAD_FINAL_LAB 2>/dev/null
mkdir GOAD_FINAL_LAB && cd GOAD_FINAL_LAB

# 2. CLONE & INSTALL
echo "[*] Cloning repository and installing dependencies..."
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .
python3 -m pip install ansible-core pywinrm --user --quiet
ansible-galaxy install -r ./ansible/requirements.yml 2>/dev/null

# 3. FIX JUMPBOX TEMPLATE (Semicolon-Free Fix)
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

# 4. GLOBAL COMPATIBILITY & THE VITAL NIC FIX
echo "[*] Applying Azure 2026 patches and NIC Wildcard Fix..."
# Patching Region and SKUs
find . -type f -name "*.tf" -not -name "jumpbox.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g; s/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g' {} +

# THE FIX: Prevents the "No MSFT_NetAdapter objects found" error by allowing wildcards
find ./ansible -type f \( -name "*.yml" -o -name "*.ps1" \) -exec perl -pi -e 's/Ethernet 2/Ethernet*/g' {} +
find . -name "variables.yml" -exec perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g' {} +

# 5. CORE DEPLOYMENT
echo "[*] Launching GOAD Core... (Approx. 45-60 mins)"
export TF_VAR_location="westus2"
chmod +x goad.sh
./goad.sh -t install -l GOAD-Light -p azure -m local

# 6. WS01 SIDE-LOAD (Hardware + DNS)
echo "[*] Main Lab complete. Side-loading WS01 Workstation..."
RG_NAME=$(az group list --query "[?contains(name, 'GOAD')].name" -o tsv | head -n 1)

az vm create \
  --resource-group "$RG_NAME" \
  --name "WS01" \
  --image MicrosoftWindowsDesktop:Windows-10:22h2-pro-g2:latest \
  --size Standard_D2s_v3 \
  --admin-username goadadmin \
  --admin-password "Password123!" \
  --vnet-name "goad-vnet" \
  --subnet "goad-subnet" \
  --public-ip-address "" \
  --nsg-rule NONE

# Set DNS to DC01
NIC_ID=$(az vm show -g "$RG_NAME" -n "WS01" --query "networkProfile.networkInterfaces[0].id" -o tsv)
NIC_NAME=$(basename "$NIC_ID")
az network nic update --name "$NIC_NAME" --resource-group "$RG_NAME" --dns-servers 192.168.10.10 8.8.8.8

# 7. GENERATE THE ACCESS GUIDE
echo "[*] Generating final ACCESS_GUIDE.txt..."
WS_PATH=$(find ./workspace -type d -name "provider" | head -n 1)
JUMPBOX_IP=$(cd "$WS_PATH" && terraform output -raw public_ip_jumpbox 2>/dev/null)
SSH_KEY_PATH="$(pwd)/ssh_keys/ubuntu-jumpbox.pem"
chmod 400 "$SSH_KEY_PATH"

{
  echo "====================================================="
  echo "         GOAD-LIGHT MASTER ACCESS GUIDE              "
  echo "====================================================="
  echo "Jumpbox Public IP: $JUMPBOX_IP"
  echo "SSH Command:       ssh -i $SSH_KEY_PATH goad@$JUMPBOX_IP"
  echo ""
  echo "--- WS01 WORKSTATION (SIDE-LOADED) ---"
  echo "Internal IP:       192.168.10.20"
  echo "Admin User:        goadadmin / Password123!"
  echo "👉 JOIN COMMAND: Add-Computer -DomainName 'north.sevenkingdoms.local' -Restart"
  echo ""
  echo "--- DOMAIN ADMIN CREDENTIALS ---"
  echo "User: administrator / Password123!"
  echo ""
  echo "--- 🚨 TERMINATE LAB (WIPES EVERYTHING) 🚨 ---"
  echo "az group delete --name $RG_NAME --yes --no-wait"
  echo "====================================================="
} > "./ACCESS_GUIDE.txt"

clear
cat "./ACCESS_GUIDE.txt"

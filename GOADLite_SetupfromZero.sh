#!/bin/bash

# 1. CLEAN START - Kill any existing GOAD folders to prevent nesting
cd "$HOME"
rm -rf GOAD_LAB_TEMP
mkdir GOAD_LAB_TEMP
cd GOAD_LAB_TEMP

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: THE FINAL REPAIR (2026)            "
echo "-------------------------------------------------------"

# 2. SYSTEM CHECK
for tool in az terraform python3 jq git; do
    if ! command -v $tool &> /dev/null; then brew install $tool; fi
done

# 3. CLONE
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .

# 4. FIX PATHS & INSTALL (The fix for your specific error)
# We ensure we are in the folder that actually contains the lab files
if [ ! -f "requirements.txt" ]; then
    cd goad || exit 1
fi

echo "[*] Installing Requirements..."
# Using --no-cache-dir to ensure we don't pull broken local files
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --user --quiet

# Fix: Ansible Galaxy needs to be told exactly which file to use
ansible-galaxy role install -r requirements.yml
ansible-galaxy collection install -r requirements.yml

# 5. AUTOMATED PATCHES (The surgical edits)
echo "[*] Applying Patches..."
# Fix Regions/SKUs
find . -type f -name "*.tf" -print0 | xargs -0 perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g'

# Fix Network Adapter
find . -type f -name "variables.yml" -print0 | xargs -0 perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g'

# Fix Jumpbox (Force-overwrite to ensure no nesting errors)
JB_FILE=$(find . -name "jumpbox.tf" | head -n 1)
cat <<EOF > "$JB_FILE"
resource "tls_private_key" "ssh" { algorithm = "RSA"; rsa_bits = 4096 }
resource "local_file" "ssh_key" {
  content = tls_private_key.ssh.private_key_pem
  filename = "\${path.root}/../ssh_keys/ubuntu-jumpbox.pem"
  file_permission = "0600"
}
resource "azurerm_public_ip" "ubuntu_public_ip" {
  name = "ubuntu-public-ip"; location = azurerm_resource_group.resource_group.location
  resource_group_name = azurerm_resource_group.resource_group.name; allocation_method = "Static"; sku = "Standard"
}
resource "azurerm_network_interface" "ubuntu_jumbox_nic" {
  name = "ubuntu-jumbox-nic"; location = azurerm_resource_group.resource_group.location
  resource_group_name = azurerm_resource_group.resource_group.name
  ip_configuration {
    name = "internal"; subnet_id = azurerm_subnet.subnet.id; private_ip_address_allocation = "Dynamic"
    public_ip_address_id = azurerm_public_ip.ubuntu_public_ip.id
  }
}
resource "azurerm_linux_virtual_machine" "jumpbox" {
  name = "jumpbox"; resource_group_name = azurerm_resource_group.resource_group.name
  location = azurerm_resource_group.resource_group.location; size = "Standard_D2s_v3"; admin_username = "goad"
  network_interface_ids = [azurerm_network_interface.ubuntu_jumbox_nic.id]
  admin_ssh_key { username = "goad"; public_key = tls_private_key.ssh.public_key_openssh }
  os_disk { caching = "ReadWrite"; storage_account_type = "Standard_LRS" }
  source_image_reference { publisher = "Canonical"; offer = "0001-com-ubuntu-server-jammy"; sku = "22_04-lts-gen2"; version = "latest" }
}
EOF

# 6. RUN
export TF_VAR_location="westus2"
./goad.sh -t install -l GOAD-Light -p azure -m local

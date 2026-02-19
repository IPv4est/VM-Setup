
#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: THE EXORCIST DEPLOYER (2026)       "
echo "  Cleaning Caches and Fixing Terraform Syntax...       "
echo "-------------------------------------------------------"

# 1. ESCAPE & NUKE ALL OLD FOLDERS
# This ensures no "GOAD" or "GOAD_DEPLOY" folders are polluting your path
cd "$HOME"
rm -rf GOAD_FINAL_FIX GOAD_DEPLOY GOAD_TOTAL_RESET GOAD_LAB_TEMP 2>/dev/null
mkdir GOAD_FINAL_FIX && cd GOAD_FINAL_FIX

# 2. SYSTEM CHECK
for tool in az terraform python3 jq git; do
    if ! command -v $tool &> /dev/null; then brew install $tool; fi
done

# 3. AZURE AUTHENTICATION
if ! az account show --output none 2>/dev/null; then
    az login --output table
fi

# 4. CLEAN CLONE
echo "[*] Cloning fresh repository..."
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .

# 5. INSTALL REQUIREMENTS
python3 -m pip install ansible-core pywinrm --user --quiet
if [ -f "./ansible/requirements.yml" ]; then
    ansible-galaxy install -r ./ansible/requirements.yml
fi

# 6. GLOBAL PATCHING (Source Files)
echo "[*] Patching Source Files..."
find . -type f -name "*.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g' {} +
find . -type f -name "*.tf" -exec perl -pi -e 's/sku\s*=\s*"Basic"/sku = "Standard"/g' {} +
find . -type f -name "*.tf" -exec perl -pi -e 's/Standard_B2s/Standard_D2s_v3/g' {} +

# 7. THE JUMPBOX REWRITE (Multi-line, No Semicolons)
# We find the jumpbox file and FORCE a clean, valid version onto it
JB_FILE=$(find . -name "jumpbox.tf" | head -n 1)
echo "[*] Force-writing clean Jumpbox to $JB_FILE..."
cat <<'EOF' > "$JB_FILE"
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "ssh_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = "${path.root}/../ssh_keys/ubuntu-jumpbox.pem"
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

# 8. THE FINAL KILL-SWITCH (Delete Workspace Cache)
# This prevents goad.sh from using the old, broken jumpbox.tf
echo "[*] Naking workspace cache..."
rm -rf workspace/* 2>/dev/null

# 9. LAUNCH
echo "[*] Launching GOAD..."
export TF_VAR_location="westus2"
chmod +x goad.sh
./goad.sh -t install -l GOAD-Light -p azure -m local

#!/bin/bash

echo "-------------------------------------------------------"
echo "    GOAD-Light Azure: UNIFIED MASTER BUILDER           "
echo "-------------------------------------------------------"

# 1. CLEAN START
# Removed version-specific folder naming
cd "$HOME"
rm -rf GOAD_AZURE_DEPLOYMENT 2>/dev/null
mkdir GOAD_AZURE_DEPLOYMENT && cd GOAD_AZURE_DEPLOYMENT

# 2. CLONE & INSTALL
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .
python3 -m pip install ansible-core pywinrm --user --quiet
ansible-galaxy install -r ./ansible/requirements.yml 2>/dev/null

# 3. FIX JUMPBOX TEMPLATE (Standardized SSH & Network)
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

# 4. AGGRESSIVE NIC & REGION PATCHING
echo "[*] Applying Universal patches..."
find . -type f -name "*.tf" -not -name "jumpbox.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g; s/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g' {} +
find . -type f \( -name "*.yml" -o -name "*.ps1" \) -exec sed -i '' 's/InterfaceAlias "Ethernet"/InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).InterfaceIndex/g' {} +
find . -name "*.tf" -exec sed -i '' 's/win10-21h2-pro-g2/win10-22h2-pro-g2/g' {} +

# 5. CORE DEPLOYMENT
echo "[*] Launching GOAD Core Deployment..."
export TF_VAR_location="westus2"
chmod +x goad.sh
./goad.sh -t install -l GOAD-Light -p azure -m local

# 6. WS01 SIDE-LOAD
echo "[*] Main Lab complete. Attempting WS01 Side-load..."
RG_NAME=$(az group list --query "[?contains(name, 'GOAD')].name" -o tsv | head -n 1)

if [ ! -z "$RG_NAME" ]; then
    az vm create \
      --resource-group "$RG_NAME" \
      --name "WS01" \
      --image "MicrosoftWindowsDesktop:Windows-10:win10-22h2-pro-g2:latest" \
      --size "Standard_D2s_v3" \
      --admin-username goadadmin \
      --admin-password "Password123!" \
      --vnet-name "goad-vnet" \
      --subnet "goad-subnet" \
      --private-ip-address "192.168.56.22" \
      --public-ip-address "" 

    # 7. POST-DEPLOYMENT HYDRATION (THE EXPIRED PASSWORD FIX)
    echo "[*] Applying WS01 'Expired Password' and RDP Fixes..."
    
    az vm run-command invoke -g "$RG_NAME" -n "WS01" --command-id RunPowerShellScript --scripts "
    net user goadadmin Password123! /active:yes;
    net user labadmin Password123! /add;
    net localgroup administrators labadmin /add;
    wmic useraccount where name='goadadmin' set passwordexpires=false;
    wmic useraccount where name='labadmin' set passwordexpires=false;
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0;
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 1;
    Restart-Service TermService -Force;
    Set-DnsClientServerAddress -InterfaceAlias 'Ethernet*' -ServerAddresses ('192.168.56.10')
    "
else
    echo "[!] ERROR: No GOAD Resource Group found."
fi

# 8. GENERATE VERBOSE ACCESS GUIDE
JUMPBOX_IP=$(az network public-ip show -g "$RG_NAME" -n "ubuntu-public-ip" --query "ipAddress" -o tsv)
SSH_KEY_PATH="$(pwd)/ssh_keys/ubuntu-jumpbox.pem"
chmod 400 "$SSH_KEY_PATH"

{
  echo "====================================================="
  echo "         GOAD-LIGHT INFRASTRUCTURE ACCESS GUIDE      "
  echo "====================================================="
  echo "1. ESTABLISH THE SSH TUNNEL"
  echo "-----------------------------------------------------"
  echo "Open a fresh terminal on your Mac and run:"
  echo "ssh -i $SSH_KEY_PATH -L 3390:192.168.56.22:3389 goad@$JUMPBOX_IP"
  echo ""
  echo "KEEP THIS TERMINAL OPEN. This maps the remote WS01 RDP "
  echo "port to your local machine at port 3390."
  echo ""
  echo "2. CONNECT VIA REMOTE DESKTOP"
  echo "-----------------------------------------------------"
  echo "Open Microsoft Remote Desktop and add a new PC:"
  echo "PC Name:           127.0.0.1:3390"
  echo "User Account:      Choose 'Ask when required'"
  echo ""
  echo "When prompted for credentials, use:"
  echo "Username:          .\labadmin   (or .\goadadmin)"
  echo "Password:          Password123!"
  echo ""
  echo "3. TROUBLESHOOTING EXPIRED PASSWORDS"
  echo "-----------------------------------------------------"
  echo "If you receive error 0x207, the NLA bypass in Section 7"
  echo "of the script ensures you can reach the Windows login"
  echo "screen inside the RDP window. If it asks for a change,"
  echo "you can now perform it manually within that window."
  echo ""
  echo "4. DOMAIN INFORMATION"
  echo "-----------------------------------------------------"
  echo "Domain:            north.sevenkingdoms.local"
  echo "Domain Controller: 192.168.56.10 (KingsLanding)"
  echo "Workstation IP:    192.168.56.22"
  echo "====================================================="
} > "./ACCESS_GUIDE.txt"

cat "./ACCESS_GUIDE.txt"

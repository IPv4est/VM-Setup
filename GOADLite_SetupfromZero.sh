#!/bin/bash

echo "-------------------------------------------------------"
echo "  GOAD-Light Azure: THE FINAL IRONCLAD DEPLOYER        "
echo "  Resetting Environment and Launching from Zero...     "
echo "-------------------------------------------------------"

# 1. TOTAL ENVIRONMENT RESET
# We use a brand new directory name to ensure no old, broken files persist
cd "$HOME"
rm -rf GOAD_FINAL_FIX 2>/dev/null
mkdir GOAD_FINAL_FIX
cd GOAD_FINAL_FIX

# 2. SYSTEM DEPENDENCY CHECK
echo "[*] Verifying system tools..."
for tool in az terraform python3 jq git; do
    if ! command -v $tool &> /dev/null; then 
        echo "[*] Installing $tool via Homebrew..."
        brew install $tool
    fi
done

# 3. AZURE AUTHENTICATION
echo "[*] Checking Azure login status..."
if ! az account show --output none 2>/dev/null; then
    echo "[*] Please login to Azure in the browser window..."
    az login --output table
fi

# 4. CLEAN CLONE
echo "[*] Cloning fresh GOAD Lab repository..."
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .

# 5. INSTALL REQUIREMENTS
echo "[*] Installing Python and Ansible dependencies..."
# Direct install of core tools since requirements.txt is deprecated in new GOAD versions
python3 -m pip install --upgrade pip --quiet
python3 -m pip install ansible-core pywinrm --user --quiet

# Target the actual Ansible requirements file
if [ -f "./ansible/requirements.yml" ]; then
    echo "[+] Installing Ansible Galaxy roles from subfolder..."
    ansible-galaxy install -r ./ansible/requirements.yml
elif [ -f "./requirements.yml" ]; then
    echo "[+] Installing Ansible Galaxy roles from root..."
    ansible-galaxy install -r ./requirements.yml
fi

# 6. GLOBAL COMPATIBILITY PATCHES (Semicolon-Safe)
echo "[*] Patching Terraform files for Azure 2026 compatibility..."

# Fix Regions: Europe -> West US 2
find . -type f -name "*.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g' {} +

# Fix SKUs: Basic/Dynamic -> Standard/Static
find . -type f -name "*.tf" -exec perl -pi -e 's/sku\s*=\s*"Basic"/sku = "Standard"/g' {} +
find . -type f -name "*.tf" -exec perl -pi -e 's/allocation_method\s*=\s*"Dynamic"/allocation_method = "Static"/g' {} +

# Fix VM Sizes: B2s -> D2s_v3 (More reliable for 2026 workloads)
find . -type f -name "*.tf" -exec perl -pi -e 's/Standard_B2s/Standard_D2s_v3/g' {} +

# Fix Semicolon Error: Nuke any semicolons that might have snuck into .tf files
find . -type f -name "*.tf" -exec perl -pi -e 's/;//g' {} +

# 7. NETWORK ADAPTER PATCH
echo "[*] Patching network adapter wildcards..."
find . -name "variables.yml" -exec perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g' {} +

# 8. WORKSPACE PREP & LAUNCH
echo "[*] Preparing workspace and starting Terraform..."
# Ensure the workspace is fresh
rm -rf workspace/* 2>/dev/null

# Set the environment variable for the Azure region
export TF_VAR_location="westus2"

# Ensure the main script is executable
chmod +x goad.sh

# FINAL EXECUTION
./goad.sh -t install -l GOAD-Light -p azure -m local

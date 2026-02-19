#!/bin/bash

# 1. ESCAPE NESTED FOLDERS
# This ensures we aren't running inside an old GOAD folder
cd "$HOME"
rm -rf GOAD_DEPLOYMENT_TEMP
mkdir GOAD_DEPLOYMENT_TEMP
cd GOAD_DEPLOYMENT_TEMP

echo "[*] Cloning fresh repository into $(pwd)..."
git clone --depth 1 https://github.com/Orange-Cyberdefense/GOAD.git .

# 2. THE PATH CHECK
# If we see 'goadpath.py', we are in the WRONG folder. 
# We need to see 'goad.sh' and 'requirements.txt'
if [ ! -f "requirements.txt" ]; then
    echo "[-] Critical error: Clone did not place requirements.txt in root."
    ls -F
    exit 1
fi

# 3. INSTALL REQUIREMENTS
echo "[*] Installing Requirements..."
# We use the full path to the python binary to avoid Mac environment confusion
export PATH="$PATH:/usr/local/bin"
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --user --quiet

# Fix: Ansible Galaxy needs to be told exactly which file to use
# We call it through python3 -m to ensure it uses the pip-installed version
python3 -m ansible galaxy role install -r requirements.yml
python3 -m ansible galaxy collection install -r requirements.yml

# 4. PATCHING
echo "[*] Applying Azure 2026 Patches..."
# Use relative paths from ROOT to avoid the nesting issue
find . -maxdepth 4 -name "*.tf" -exec perl -pi -e 's/westeurope|europe/westus2/g; s/sku\s*=\s*"Basic"/sku = "Standard"/g; s/Standard_B2s/Standard_D2s_v3/g' {} +

# Network Fix
find . -name "variables.yml" -exec perl -pi -e 's/adapter_names: "Ethernet"/adapter_names: "Ethernet*"/g' {} +

# 5. RUN
export TF_VAR_location="westus2"
chmod +x goad.sh
./goad.sh -t install -l GOAD-Light -p azure -m local

#!/bin/bash

echo "Installing ADE and dependencies..."
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check and install a package
install_if_missing() {
    local package=$1
    local binary=$2
    local install_command=$3
    local logfile="/tmp/ade_install_${package}.log"
    
    # Check if binary exists in PATH first
    if command -v "$binary" &>/dev/null; then
        echo -e "${GREEN}✓ $package is already installed (found $binary in PATH), skipping...${NC}"
        return 0
    fi
    
    # Check if installed via pipx
    if pipx list 2>/dev/null | grep -q "package $package"; then
        echo -e "${GREEN}✓ $package is already installed via pipx, skipping...${NC}"
        return 0
    fi
    
    # Not installed, proceed with installation
    echo -e "${BLUE}→ Installing $package...${NC}"
    eval "$install_command" &>"$logfile"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $package installed successfully${NC}"
        rm -f "$logfile"
        return 0
    else
        echo -e "${RED}✗ Failed to install $package (see $logfile for details)${NC}"
        return 1
    fi
}

# Export function so subshells can use it
export -f install_if_missing
export GREEN RED YELLOW BLUE NC

# Array to store background process IDs and package names
declare -A pids

# Install each tool in parallel
# Syntax: install_if_missing "package_name" "binary_name" "install_command"
install_if_missing "netexec" "nxc" "pipx install git+https://github.com/Pennyw0rth/NetExec" &
pids[netexec]=$!

install_if_missing "certipy-ad" "certipy-ad" "pipx install certipy-ad" &
pids[certipy-ad]=$!

install_if_missing "bloodhound-ce" "bloodhound-ce-python" "pipx install bloodhound-ce" &
pids[bloodhound-ce]=$!

install_if_missing "bloodyAD" "bloodyAD" "pipx install bloodyAD" &
pids[bloodyAD]=$!

install_if_missing "impacket" "impacket-smbserver" "pipx install impacket" &
pids[impacket]=$!

# Wait for all background processes to complete
echo ""
echo -e "${YELLOW}⏳ Waiting for parallel installations to complete...${NC}"
failed=0
for package in "${!pids[@]}"; do
    wait ${pids[$package]}
    if [ $? -ne 0 ]; then
        failed=1
    fi
done

echo ""
if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✓ All parallel installations completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ Some installations failed, check logs in /tmp/${NC}"
fi

# Install ade last (after dependencies are ready)
echo ""
install_if_missing "ade" "ade" "pipx install ."

echo ""
echo -e "${GREEN}Installation complete!${NC}"

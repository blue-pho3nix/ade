#!/bin/bash

echo "Installing ADE and dependencies..."
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to install a package with pipx
install_package() {
    local package=$1
    local install_command=$2
    local logfile="/tmp/ade_install_${package}.log"
    
    echo -e "${BLUE}→ Installing $package...${NC}"
    eval "$install_command" &>"$logfile"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $package installed successfully${NC}"
        rm -f "$logfile"
        return 0
    else
        # Check if it's already installed (pipx will error if already installed)
        if grep -q "already seems to be installed" "$logfile" || grep -q "already installed" "$logfile"; then
            echo -e "${GREEN}✓ $package is already installed, skipping...${NC}"
            rm -f "$logfile"
            return 0
        else
            echo -e "${RED}✗ Failed to install $package (see $logfile for details)${NC}"
            return 1
        fi
    fi
}

# Export function so subshells can use it
export -f install_package
export GREEN RED YELLOW BLUE NC

# Array to store background process IDs and package names
declare -A pids

# Install each tool in parallel
echo "Installing all packages with pipx..."
echo ""

install_package "netexec" "pipx install git+https://github.com/Pennyw0rth/NetExec" &
pids[netexec]=$!

install_package "nxc" "pipx install nxc" &
pids[nxc]=$!

install_package "certipy-ad" "pipx install certipy-ad" &
pids[certipy-ad]=$!

install_package "bloodhound-ce" "pipx install bloodhound-ce" &
pids[bloodhound-ce]=$!

install_package "bloodyad" "pipx install bloodyAD" &
pids[bloodyad]=$!

install_package "impacket" "pipx install impacket" &
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
install_package "ade" "pipx install ."

echo ""
echo -e "${GREEN}Installation complete!${NC}"

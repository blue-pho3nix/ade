#!/bin/bash
echo "Installing ADE and dependencies..."
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if a package is installed via pipx
is_package_installed() {
    local package=$1
    pipx list 2>/dev/null | grep -q "package $package"
}

# Function to install a package with pipx
install_package() {
    local package=$1
    local install_cmd=$2
    
    if is_package_installed "$package"; then
        echo -e "${YELLOW}⊙ $package is already installed, skipping${NC}"
        return 0
    fi
    
    echo -e "${BLUE}→ Installing $package...${NC}"
    if $install_cmd &>/dev/null; then
        echo -e "${GREEN}✓ $package installed successfully${NC}"
    else
        echo -e "${RED}✗ Failed to install $package${NC}"
    fi
}

export -f install_package
export -f is_package_installed
export GREEN RED YELLOW BLUE NC

# Install packages in parallel
install_package "netexec" "pipx install git+https://github.com/Pennyw0rth/NetExec" &
install_package "certipy-ad" "pipx install certipy-ad" &
install_package "bloodyad" "pipx install bloodyAD" &
install_package "impacket" "pipx install impacket" &
install_package "bloodhound-ce" "pipx install bloodhound-ce" &

# Wait for all background jobs
wait
echo ""
echo -e "${BLUE}Installing ADE${NC}"
install_package "ade" "pipx install git+https://github.com/blue-pho3nix/ade.git"

echo ""
echo -e "${GREEN}Installation complete!${NC}"

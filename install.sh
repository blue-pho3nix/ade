#!/bin/bash
echo "Installing ADE and dependencies..."
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ask user which package manager to use
echo -e "${BLUE}Which Python package manager would you like to use?${NC}"
echo "  1) pipx"
echo "  2) uv"
echo ""
read -p "Enter your choice [1/2]: " choice

case $choice in
    1)
        PKG_MANAGER="pipx"
        ;;
    2)
        PKG_MANAGER="uv"
        ;;
    *)
        echo -e "${YELLOW}Invalid choice, defaulting to pipx${NC}"
        PKG_MANAGER="pipx"
        ;;
esac

echo ""
echo -e "${BLUE}Using $PKG_MANAGER for package installation${NC}"

# Detect Python version and handle compatibility
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

# Check if Python version is 3.14 or higher (PyO3 compatibility issue)
USE_PYTHON_313=false
if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 14 ]; then
    echo -e "${YELLOW}⚠ Python $PYTHON_VERSION detected. Some packages require Python ≤3.13 for PyO3 compatibility.${NC}"
    if [ "$PKG_MANAGER" = "uv" ]; then
        echo -e "${BLUE}  → Will use --python 3.13 for package installations${NC}"
        USE_PYTHON_313=true
    else
        echo -e "${BLUE}  → Setting PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1${NC}"
    fi
    export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
fi
echo ""

# Function to check and install pipx
ensure_pipx() {
    if command -v pipx &>/dev/null; then
        echo -e "${GREEN}✓ pipx is already installed${NC}"
        return 0
    fi
    
    echo -e "${BLUE}→ Installing pipx...${NC}"
    if command -v brew &>/dev/null; then
        brew install pipx &>/dev/null && pipx ensurepath &>/dev/null
    elif command -v apt &>/dev/null; then
        sudo apt update &>/dev/null && sudo apt install -y pipx &>/dev/null && pipx ensurepath &>/dev/null
    else
        python3 -m pip install --user pipx &>/dev/null && python3 -m pipx ensurepath &>/dev/null
    fi
    
    if command -v pipx &>/dev/null; then
        echo -e "${GREEN}✓ pipx installed successfully${NC}"
    else
        echo -e "${RED}✗ Failed to install pipx${NC}"
        exit 1
    fi
}

# Function to check and install uv
ensure_uv() {
    if command -v uv &>/dev/null; then
        echo -e "${GREEN}✓ uv is already installed${NC}"
        return 0
    fi
    
    echo -e "${BLUE}→ Installing uv...${NC}"
    if curl -LsSf https://astral.sh/uv/install.sh | sh &>/dev/null; then
        # Source the shell config to get uv in PATH
        export PATH="$HOME/.local/bin:$PATH"
        if command -v uv &>/dev/null; then
            echo -e "${GREEN}✓ uv installed successfully${NC}"
        else
            echo -e "${RED}✗ Failed to install uv (not found in PATH)${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ Failed to install uv${NC}"
        exit 1
    fi
}

# Ensure the selected package manager is installed
if [ "$PKG_MANAGER" = "pipx" ]; then
    ensure_pipx
else
    ensure_uv
fi
echo ""

# Function to check if a package is installed
is_package_installed() {
    local package=$1
    if [ "$PKG_MANAGER" = "pipx" ]; then
        pipx list 2>/dev/null | grep -q "package $package"
    else
        uv tool list 2>/dev/null | grep -q "^$package"
    fi
}

# Function to install a package
install_package() {
    local package=$1
    local install_source=$2
    
    if is_package_installed "$package"; then
        echo -e "${YELLOW}⊙ $package is already installed, skipping${NC}"
        return 0
    fi
    
    echo -e "${BLUE}→ Installing $package...${NC}"
    if [ "$PKG_MANAGER" = "pipx" ]; then
        if pipx install "$install_source" &>/dev/null; then
            echo -e "${GREEN}✓ $package installed successfully${NC}"
        else
            echo -e "${RED}✗ Failed to install $package${NC}"
        fi
    else
        local uv_cmd="uv tool install"
        if [ "$USE_PYTHON_313" = "true" ]; then
            uv_cmd="uv tool install --python 3.13"
        fi
        if $uv_cmd "$install_source" &>/dev/null; then
            echo -e "${GREEN}✓ $package installed successfully${NC}"
        else
            echo -e "${RED}✗ Failed to install $package${NC}"
        fi
    fi
}

export -f install_package
export -f is_package_installed
export PKG_MANAGER USE_PYTHON_313 PYO3_USE_ABI3_FORWARD_COMPATIBILITY GREEN RED YELLOW BLUE NC

# Install packages in parallel
install_package "netexec" "git+https://github.com/Pennyw0rth/NetExec" &
install_package "certipy-ad" "certipy-ad" &
install_package "bloodyad" "bloodyAD" &
install_package "impacket" "impacket" &
install_package "bloodhound-ce" "bloodhound-ce" &

# Wait for all background jobs
wait
echo ""
echo -e "${BLUE}Installing ADE${NC}"
install_package "ade" "git+https://github.com/blue-pho3nix/ade.git"

echo ""
echo -e "${GREEN}Installation complete!${NC}"

#!/bin/bash

echo "Uninstalling ADE and dependencies (pipx versions only)..."
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check and uninstall a package
uninstall_if_exists() {
    local package=$1
    
    # Check if installed via pipx
    if pipx list 2>/dev/null | grep -q "package $package"; then
        echo -e "${BLUE}→ Uninstalling $package...${NC}"
        pipx uninstall "$package" &>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${RED}✓ $package uninstalled successfully${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to uninstall $package${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠ $package is not installed via pipx, skipping...${NC}"
        return 0
    fi
}

# Export function so subshells can use it
export -f uninstall_if_exists
export GREEN RED YELLOW BLUE NC

# Array to store background process IDs and package names
declare -A pids

# Uninstall ade first
uninstall_if_exists "ade"

echo ""
echo -e "${BLUE}Uninstalling dependencies in parallel...${NC}"
echo ""

# Uninstall each tool in parallel
uninstall_if_exists "netexec" &
pids[netexec]=$!

uninstall_if_exists "certipy-ad" &
pids[certipy-ad]=$!

uninstall_if_exists "bloodhound-ce" &
pids[bloodhound-ce]=$!

uninstall_if_exists "bloodyAD" &
pids[bloodyAD]=$!

uninstall_if_exists "impacket" &
pids[impacket]=$!

# Wait for all background processes to complete
echo ""
echo -e "${YELLOW}⏳ Waiting for parallel uninstallations to complete...${NC}"
failed=0
for package in "${!pids[@]}"; do
    wait ${pids[$package]}
    if [ $? -ne 0 ]; then
        failed=1
    fi
done

echo ""
if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✓ All uninstallations completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ Some uninstallations failed${NC}"
fi

# Clean up any leftover log files
if [ -d "/tmp" ]; then
    rm -f /tmp/ade_install_*.log 2>/dev/null
    echo -e "${GREEN}✓ Cleaned up installation logs${NC}"
fi

echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"

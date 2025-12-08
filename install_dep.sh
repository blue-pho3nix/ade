#!/bin/bash

echo "Installing AD Enumeration Dependencies..."

# Update and install basics
sudo apt update
sudo apt install -y nmap pipx

# Install Python tools
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install certipy-ad
pipx install bloodhound-ce
pipx install bloodyAD

# Ask about Impacket
echo ""
echo "Choose Impacket installation:"
echo "1) pipx (commands: GetNPUsers.py, getTGT.py, etc.)"
echo "2) apt  (commands: impacket-GetNPUsers, impacket-getTGT, etc.)"
read -p "Choice [1]: " choice
choice=${choice:-1}

if [ "$choice" = "2" ]; then
    sudo apt install -y impacket-scripts
else
    pipx install impacket
fi

# Ensure path
pipx ensurepath --force

echo ""
echo "Done! Run: source ~/.bashrc"

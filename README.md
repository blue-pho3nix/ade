# ADE
ADE is a Python script that automates Active Directory (AD) enumeration in lab environments, helping users on Hack The Box, Hack Smarter, TryHackMe, Proving Grounds, or exams like OSCP and CPTS streamline initial AD recon.

**Credentials Example**
<img width="2116" height="847" alt="image" src="https://github.com/user-attachments/assets/67889c87-bcf1-4759-a05f-7202b3036b1d" />

**Kerberos Example**
<img width="2127" height="1073" alt="image" src="https://github.com/user-attachments/assets/b17a4c17-7944-4254-89a1-ff36c62d45e3" />

**No Credentials Example**
<img width="2148" height="1146" alt="image" src="https://github.com/user-attachments/assets/d5295138-d22f-4ccf-98df-ab7703486ee6" />


## Key Features
### Initial Discovery & Host Setup
- **Target Alive Checks:** Pings the target with nmap before starting to ensure the IP is correct and the host is online.
- **/etc/hosts Management:** Discovers the target's FQDN and domain, then maps them in /etc/hosts for name resolution.
- **Credential Validation:** Checks if supplied credentials are valid before launching deeper scans to avoid failed authenticated runs.
- **User & description enumeration:** Collects sAMAccountName and description attributes via LDAP, and uses SMB-based RID cycling as a fallback to find accounts that LDAP queries might not return

### Initial Access & Credential Attacks
- **User Spraying:** If run without credentials, it attempts user:user logins for all discovered accounts.
- **AS-REP Roasting:** Uses the generated users.txt to find accounts vulnerable to offline password cracking.
- **Kerberoasting:** Searches for service accounts and requests their tickets, providing hashes to crack offline.
- **Auto-Kerberos Switching:** Detects if Kerberos is required. If NTLM is unsupported, ADE enables Kerberos mode and restarts the workflow.

### Post-Authentication Enumeration
- **Kerberos Ticket Management:** Gets a Kerberos ticket, saves it as a .ccache file you can reuse, and tells you the command to connect to SMB using that ticket.
- **SMB share enumeration:** Enumerates SMB shares on the target, attempts access with anonymous/guest or supplied credentials, and reports access permissions (e.g., READ, WRITE).
- **Intelligent retries:** Automatically retries SMB checks when they fail to ensure more reliable results.
- **BloodHound collection:** Executes the BloodHound data collector, automatically retrying on failure, and outputs a ZIP that can be imported into BloodHound.
- **Permission Checks:** Scans Active Directory with bloodyAD to find items your credentials can change (like user accounts or groups).
- **ADCS checks:** Probes for Active Directory Certificate Services and then uses Certipy to find misconfigured templates that allow for privilege escalation.

---

## Install Dependencies

### Install [termcolor](https://pypi.org/project/termcolor/)

```
sudo apt update && sudo apt install python3-termcolor
```
#### OR
**Step 1:** Create virutal environment 
```
python3 -m venv ade-venv
```
**Step 2:** Activate the virtual environment
```
source ade-venv/bin/activate
```
**Step 3:** Install the required Python package
```
python3 -m pip install termcolor
```
### Install [Nmap](https://nmap.org/)

```
sudo apt update && sudo apt install nmap
```

### Install [Certipy](https://github.com/ly4k/Certipy), [Impacket](https://github.com/fortra/impacket), [bloodyAD](https://github.com/CravateRouge/bloodyAD), [NetExec](https://github.com/Pennyw0rth/NetExec),  [bloodhound-ce](http://github.com/dirkjanm/BloodHound.py)

**Step 1:** Install `pipx` and `git`
```
sudo apt update && sudo apt install pipx git
```
**Step 2:** Ensure `pipx` is on your PATH
```
pipx ensurepath
```
**Step 3:** Install dependencies with `pipx`
Install each tool into its own isolated environment.
```
pipx install certipy-ad
pipx install impacket
pipx install bloodyAD
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install bloodhound-ce
```

## Usage
> Wait at least 5 minutes after starting your lab before running the script to make sure `nxc --shares` works. 
> </br> This is because some labs take longer to start up.

Without credentials (anonymous/guest checks):
```
python3 ade.py -r <box-ip>
```

With credentials (authenticated checks):
```
python ade.py -r <box-ip> -u <user> -p <password> 
```

---

> NOTE:  If you have any issues or requests, reach out on [Discord](https://discord.gg/TujAjYXJjr) (Blue Pho3nix).

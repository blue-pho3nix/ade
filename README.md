# ADE
ADE is a Python script that automates Active Directory (AD) enumeration in lab environments, helping users on Hack The Box, Hack Smarter, TryHackMe, Proving Grounds, or exams like OSCP and CPTS streamline initial AD recon.

<img width="2116" height="847" alt="image" src="https://github.com/user-attachments/assets/67889c87-bcf1-4759-a05f-7202b3036b1d" />

## Installation

```
pipx install git+'https://github.com/blue-pho3nix/ade.git'
```

### Uninstall apt Impacket
You may need to uninstall the apt version of impacket to not get any conflicts with the pipx version of it.

## Uninstall ade

```
pipx uninstall ade
```

## Dependencies
The dependecies for the script are [certipy-ad](https://github.com/ly4k/Certipy), [netexec](https://github.com/Pennyw0rth/NetExec), [bloodhound-ce](), [bloodyAD](https://github.com/CravateRouge/bloodyAD), and [Impacket](https://github.com/fortra/impacket)

```
sudo apt remove impacket-scripts
```

## Key Features
### Initial Discovery & Host Setup
- **Target Alive Checks:** Pings the target with nmap before starting to ensure the IP is correct and the host is online.
- **/etc/hosts Management:** Discovers the target's FQDN and domain, then maps them in /etc/hosts for name resolution.
- **Credential Validation:** Checks if supplied credentials are valid before launching deeper scans to avoid failed authenticated runs.
- **User & Description Enumeration:** Collects sAMAccountName and description attributes via LDAP, and uses SMB-based RID cycling as a fallback to find accounts that LDAP queries might not return

### Initial Access & Credential Attacks
- **User Spraying:** If run without credentials, it attempts user:user logins for all discovered accounts.
- **AS-REP Roasting:** Uses the generated users.txt to find accounts vulnerable to offline password cracking.
- **Kerberoasting:** Searches for service accounts and requests their tickets, providing hashes to crack offline.
- **Auto-Kerberos Switching:** Detects if Kerberos is required. If NTLM is unsupported, ADE enables Kerberos mode and restarts the workflow.

### Post-Authentication Enumeration
- **Kerberos Ticket Management:** Gets a Kerberos ticket, saves it as a .ccache file you can reuse, and tells you the command to connect to SMB using that ticket.
- **SMB Share Enumeration:** Enumerates SMB shares on the target, attempts access with anonymous/guest or supplied credentials, and reports access permissions (e.g., READ, WRITE).
- **Intelligent Retries:** Automatically retries SMB checks when they fail to ensure more reliable results.
- **BloodHound Collection:** Executes the BloodHound data collector, automatically retrying on failure, and outputs a ZIP that can be imported into BloodHound.
- **Permission Checks:** Scans Active Directory with bloodyAD to find items your credentials can change (like user accounts or groups).
- **ADCS Checks:** Probes for Active Directory Certificate Services and then uses Certipy to find misconfigured templates that allow for privilege escalation.

## Usage
> [!TIP]
> Wait at least 5 minutes after starting your lab before running the script to make sure `nxc --shares` works. 
> </br> This is because some labs take longer to start up.

Without credentials (anonymous/guest checks):
```
ade -r <box-ip>
```

With credentials (authenticated checks):
```
ade -r <box-ip> -u <user> -p <password> 
```

---

> [!NOTE]
> If you have any issues or requests, reach out on [Discord](https://discord.gg/TujAjYXJjr) (Blue Pho3nix).

---
## Thank You

[Schlop](https://www.youtube.com/@Schlopz) made the script available as a `pipx`-installable package.

---

## TODO
- [ ] Make sure impacket-{tool} works for users who installed Impacket via apt
- [ ] Record usage/tutorial videos
- [ ] Add additional improvements and features as needed

 





# ADE

<img width="1669" height="1203" alt="image" src="https://github.com/user-attachments/assets/70d7dbc9-b4ba-41c1-b3f1-89b95d25d9b5" />


Active Directory enumeration and ADCS checks. 
For Labs: HTB, Hack Smarter, THM, CPTS, and OSCP

---

## Initial Discovery & Host Resolution

* **`/etc/hosts`:** Discovers the target's FQDN and domain. Makes sure the local `/etc/hosts` file is correctly mapped (`IP FQDN DOMAIN`), removing any incorrect IPs mapped to the domain/FQDN.
* **Username Collection:** Gets valid users. Discovered usernames are saved to **`users.txt`**. The script checks for duplicates and adds lowercase users to the file.

---

## Initial Access & Credential Attacks
* **User Spraying:** If no credentials are provided, the script tries `user:user` logins from `users.txt`, then retries using lowercase variants.
* **AS-REP Roasting:** Uses the generated username list to find accounts with Kerberos pre-authentication disabled.
* **Kerberoasting:** Searches for Service Principal Names (SPNs) and requests service TGS tickets for those SPNs.
* **Auto Kerberos Switch:** Detects when **NTLM negotiation fails** during Kerberoasting. The script automatically enables the Kerberos flag (`-k`) and restarts the entire enumeration loop with Kerberos authentication enabled.

---

## Post-Authentication Enumeration & Checks

* **SMB Enumeration:** Enumerates SMB shares (anonymous, guest, or authenticated) and attempts to download files using the spider_plus module. If no users.txt exists, the script will perform an initial RID brute to populate it (nxc smb).
* **BloodHound Collection:** Runs the BloodHound collector to capture AD relationships and attack-path information. The collector is retried automatically on failure.
* **Permission Check:** Uses **bloodyAD** to list objects the authenticated account can write to, pointing out escalation opportunities like writable group membership or modifiable user attributes.
* **ADCS Vulnerability Check:** Runs ADCS discovery via LDAP and Certipy to identify vulnerable certificate templates and enrollment paths which could be abused for privilege escalation or identity impersonation.

---

## Install Dependencies

### Install [termcolor](https://pypi.org/project/termcolor/)

```
sudo apt update && sudo apt install python3-termcolor
```
#### or 
1.
```
python3 -m venv ade-venv
```
2.
```
source ade-venv/bin/activate
```
3.
```
python3 -m pip install termcolor
```
### Install [Nmap](https://nmap.org/)

```
sudo apt update && sudo apt install nmap
```

### Install [Certipy](https://github.com/ly4k/Certipy), [Impacket](https://github.com/fortra/impacket), [bloodyAD](https://github.com/CravateRouge/bloodyAD), [NetExec](https://github.com/Pennyw0rth/NetExec),  [bloodhound-ce](http://github.com/dirkjanm/BloodHound.py)

1.
```
sudo apt update && sudo apt install pipx git
```
2.
```
pipx ensurepath
```
3.
```
pipx install certipy-ad impacket bloodyAD git+https://github.com/Pennyw0rth/NetExec bloodhound-ce
```

## Usage

Without Credentials
```
python3 ade.py -r <box-ip>
```

With Credentials
```
python ade.py -r <box-ip> -u <user> -p <password> 
```

---

NOTE: This is still under development. If you have any issues or requests reach out on [Discord](https://discord.gg/TujAjYXJjr) (Blue Pho3nix).

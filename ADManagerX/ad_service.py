from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

import ssl

import winrm
from ldap3 import (
    ALL,
    ALL_ATTRIBUTES,
    BASE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)

from .models import LdapSettings


session = None


class ADServiceError(Exception):
    pass


@dataclass
class ADConfig:
    server_uri: str
    use_ssl: bool
    bind_dn: str
    bind_password: str
    base_dn: str
    users_ou_dn: str
    computers_ou_dn: str
    groups_ou_dn: str
    upn_suffix: str
    user_search_filter: str
    safe_mode: bool
    server_name: str


def _load_config() -> ADConfig:
    global session

    cfg_db = LdapSettings.get_settings()
    if not cfg_db or not LdapSettings.is_configured():
        raise ADServiceError("LDAP settings are not configured.")

    bind_user = (cfg_db.bind_dn or "").strip()
    if "@" not in bind_user and "," not in bind_user:
        bind_user = f"{bind_user}@{cfg_db.upn_suffix}"

    session = winrm.Session(
        cfg_db.server_name,
        auth=(bind_user, cfg_db.bind_password),
        transport="ntlm",
    )

    return ADConfig(
        server_uri=cfg_db.server_uri,
        use_ssl=cfg_db.use_ssl,
        bind_dn=cfg_db.bind_dn,
        bind_password=cfg_db.bind_password,
        base_dn=cfg_db.base_dn,
        users_ou_dn=cfg_db.users_ou_dn,
        computers_ou_dn=cfg_db.computers_ou_dn,
        groups_ou_dn=cfg_db.groups_ou_dn,
        upn_suffix=cfg_db.upn_suffix,
        user_search_filter=cfg_db.user_search_filter or "(sAMAccountName={username})",
        safe_mode=bool(cfg_db.safe_mode),
        server_name=cfg_db.server_name or "",
    )


def _connect(cfg: ADConfig) -> Connection:
    tls = Tls(validate=ssl.CERT_NONE) if cfg.use_ssl else None
    server = Server(cfg.server_uri, use_ssl=cfg.use_ssl, get_info=ALL, tls=tls)

    bind_user = (cfg.bind_dn or "").strip()
    if "@" not in bind_user and "," not in bind_user:
        bind_user = f"{bind_user}@{cfg.upn_suffix}"

    return Connection(server, user=bind_user, password=cfg.bind_password, auto_bind=True)


def _search_one(
    conn: Connection,
    base_dn: str,
    search_filter: str,
    attributes: Optional[List[str]] = None,
):
    attrs = attributes or ALL_ATTRIBUTES
    ok = conn.search(
        base_dn,
        search_filter,
        search_scope=SUBTREE,
        attributes=attrs,
        size_limit=1,
    )
    if not ok or not conn.entries:
        return None
    return conn.entries[0]


def _ps_escape_single_quotes(val) -> str:
    return str(val or "").replace("'", "''")


def _username_to_upn(username: str, upn_suffix: str) -> str:
    if "@" in username:
        return username
    return f"{username}@{upn_suffix}"


def _normalize_computer_sam(name: str) -> str:
    name = (name or "").strip()
    return name if name.endswith("$") else f"{name}$"


def _run_ps(ps_script: str) -> str:
    global session

    if session is None:
        raise ADServiceError("WinRM session not initialized. Check _load_config().")

    r = session.run_ps(ps_script)

    out = (r.std_out or b"").decode(errors="ignore")
    err = (r.std_err or b"").decode(errors="ignore")

    if r.status_code != 0:
        raise ADServiceError(
            f"WinRM PowerShell failed (status={r.status_code}). STDERR={err} STDOUT={out}"
        )

    return out


def test_connection() -> None:
    cfg = _load_config()
    conn = _connect(cfg)
    conn.unbind()


def _resolve_base_dn(conn: Connection, cfg: ADConfig) -> str:
    if (cfg.base_dn or "").strip():
        return cfg.base_dn.strip()

    conn.search(
        search_base="",
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["defaultNamingContext"],
        size_limit=1,
    )
    if not conn.entries:
        raise ADServiceError("Cannot read RootDSE (defaultNamingContext). Check bind/permissions.")

    return str(conn.entries[0]["defaultNamingContext"].value)


# -----------------------------
# LDAP read helpers only
# -----------------------------

def _get_user_dn(conn: Connection, cfg: ADConfig, username: str) -> Optional[str]:
    flt = cfg.user_search_filter.format(username=username)
    entry = _search_one(conn, cfg.base_dn, flt, attributes=["distinguishedName"])
    if not entry:
        return None
    return entry.entry_dn


def _get_computer_dn(conn: Connection, cfg: ADConfig, computer_name: str) -> Optional[str]:
    sam = _normalize_computer_sam(computer_name)
    flt = f"(sAMAccountName={sam})"
    entry = _search_one(conn, cfg.base_dn, flt, attributes=["distinguishedName"])
    if not entry:
        return None
    return entry.entry_dn


def _get_group_dn(conn: Connection, cfg: ADConfig, group_name: str) -> Optional[str]:
    flt = f"(cn={group_name})"
    entry = _search_one(conn, cfg.base_dn, flt, attributes=["distinguishedName"])
    if not entry:
        return None
    return entry.entry_dn


def resolve_ou_name_to_dn(ou_name: str) -> str:
    """
    Resolve a friendly OU name like 'HR' to its full DN.
    Raises ADServiceError if not found or ambiguous.
    """
    target = (ou_name or "").strip().lower()
    if not target:
        raise ADServiceError("OU name is required.")

    ous = list_ous()
    matches = [ou for ou in ous if (ou.get("ou") or "").strip().lower() == target]

    if not matches:
        raise ADServiceError(f"OU not found: {ou_name}")

    if len(matches) > 1:
        matched_dns = ", ".join(m["dn"] for m in matches)
        raise ADServiceError(
            f"OU name '{ou_name}' is ambiguous. Multiple OUs found: {matched_dns}"
        )

    return matches[0]["dn"]


# -----------------------------
# User operations via WinRM
# -----------------------------

def _create_user_via_winrm(
    cfg: ADConfig,
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password: str,
    phone: str = "",
    department: str = "",
    description: str = "",
    hr_id: str = "",
    target_ou_dn: Optional[str] = None,
    must_change_password: bool = False,
    user_cannot_change_password: bool = False,  # kept for compatibility; not enforced here
    password_never_expires: bool = False,
    account_disabled: bool = False,
) -> str:
    username = (username or "").strip()
    first_name = (first_name or "").strip()
    last_name = (last_name or "").strip()
    email = (email or "").strip()
    password = (password or "").strip()
    phone = (phone or "").strip()
    department = (department or "").strip()
    description = (description or "").strip()
    hr_id = (hr_id or "").strip()
    ou_dn = (target_ou_dn or "").strip() or cfg.users_ou_dn

    if not username:
        raise ADServiceError("Username is required.")
    if not password:
        raise ADServiceError("Password is required.")
    if not ou_dn:
        raise ADServiceError("Target OU DN is empty and no default Users OU DN is configured.")

    display_name = f"{first_name} {last_name}".strip() or username
    upn = _username_to_upn(username, cfg.upn_suffix)

    u_username = _ps_escape_single_quotes(username)
    u_first = _ps_escape_single_quotes(first_name or username)
    u_last = _ps_escape_single_quotes(last_name or username)
    u_display = _ps_escape_single_quotes(display_name)
    u_email = _ps_escape_single_quotes(email)
    u_password = _ps_escape_single_quotes(password)
    u_phone = _ps_escape_single_quotes(phone)
    u_department = _ps_escape_single_quotes(department)
    u_description = _ps_escape_single_quotes(description)
    u_hr_id = _ps_escape_single_quotes(hr_id)
    u_ou = _ps_escape_single_quotes(ou_dn)
    u_upn = _ps_escape_single_quotes(upn)
    u_server = _ps_escape_single_quotes(cfg.server_name)

    ps_must_change = "$true" if must_change_password else "$false"
    ps_password_never_expires = "$true" if password_never_expires else "$false"
    ps_enabled = "$false" if account_disabled else "$true"

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$server = '{u_server}'
$username = '{u_username}'
$ou = '{u_ou}'
$upn = '{u_upn}'

$existing = Get-ADUser -LDAPFilter "(sAMAccountName=$username)" -Server $server -ErrorAction SilentlyContinue
if ($existing) {{
    throw "User already exists: $($existing.DistinguishedName)"
}}

$sec = ConvertTo-SecureString '{u_password}' -AsPlainText -Force

$params = @{{
    Name                  = $username
    SamAccountName        = $username
    UserPrincipalName     = $upn
    GivenName             = '{u_first}'
    Surname               = '{u_last}'
    DisplayName           = '{u_display}'
    Path                  = $ou
    AccountPassword       = $sec
    Server                = $server
    Enabled               = {ps_enabled}
    ChangePasswordAtLogon = {ps_must_change}
    PasswordNeverExpires  = {ps_password_never_expires}
}}

if ('{u_email}')       {{ $params['EmailAddress'] = '{u_email}' }}
if ('{u_description}') {{ $params['Description'] = '{u_description}' }}
if ('{u_department}')  {{ $params['Department'] = '{u_department}' }}
if ('{u_phone}')       {{ $params['OfficePhone'] = '{u_phone}' }}
if ('{u_hr_id}')       {{ $params['EmployeeID'] = '{u_hr_id}' }}

New-ADUser @params

$created = Get-ADUser -Identity '{u_username}' -Server $server -Properties DistinguishedName,Enabled,pwdLastSet,employeeID
if (-not $created) {{
    throw "User creation succeeded but could not verify the created user."
}}

Write-Output ("CREATED_DN=" + $created.DistinguishedName)
Write-Output ("VERIFY Enabled=" + $created.Enabled + " pwdLastSet=" + $created.pwdLastSet + " employeeID=" + $created.employeeID)
"""
    out = _run_ps(ps)

    created_dn = None
    for line in out.splitlines():
        if line.startswith("CREATED_DN="):
            created_dn = line.split("=", 1)[1].strip()
            break

    if not created_dn:
        raise ADServiceError(f"User was created but DN was not returned. STDOUT={out}")

    return created_dn


def _update_user_via_winrm(cfg: ADConfig, username: str, updates: dict) -> None:
    username_esc = _ps_escape_single_quotes((username or "").strip())
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    if not username_esc:
        raise ADServiceError("Username is required.")

    clean_updates = {}
    for key, value in (updates or {}).items():
        if value is None or value == "":
            continue
        clean_updates[key] = _ps_escape_single_quotes(value)

    if not clean_updates:
        return

    replace_lines = []
    for key, value in clean_updates.items():
        replace_lines.append(f"$replace['{key}'] = '{value}'")
    replace_block = "\n".join(replace_lines)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$user = Get-ADUser -Identity '{username_esc}' -Server '{server_esc}' -ErrorAction Stop
$replace = @{{}}
{replace_block}

Set-ADUser -Identity $user.DistinguishedName -Server '{server_esc}' -Replace $replace

$verify = Get-ADUser -Identity $user.DistinguishedName -Server '{server_esc}' -Properties displayName,givenName,sn,mail,telephoneNumber,department,description,employeeID
Write-Output ("UPDATED_DN=" + $verify.DistinguishedName)
"""
    out = _run_ps(ps)
    if "UPDATED_DN=" not in out:
        raise ADServiceError(f"Update executed but verification output not returned. STDOUT={out}")


def _set_user_account_disabled_via_winrm(cfg: ADConfig, username: str, disabled: bool) -> None:
    username_esc = _ps_escape_single_quotes((username or "").strip())
    server_esc = _ps_escape_single_quotes(cfg.server_name)
    cmd = "Disable-ADAccount" if disabled else "Enable-ADAccount"

    if not username_esc:
        raise ADServiceError("Username is required.")

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$user = Get-ADUser -Identity '{username_esc}' -Server '{server_esc}' -ErrorAction Stop
{cmd} -Identity $user.DistinguishedName -Server '{server_esc}'

$verify = Get-ADUser -Identity $user.DistinguishedName -Server '{server_esc}' -Properties Enabled
Write-Output ("VERIFY Enabled=" + $verify.Enabled)
"""
    out = _run_ps(ps)
    if "VERIFY Enabled=" not in out:
        raise ADServiceError(f"Account status update executed but verification output not returned. STDOUT={out}")


def _reset_password_via_winrm(cfg: ADConfig, username: str, new_password: str) -> None:
    username_esc = _ps_escape_single_quotes(username)
    password_esc = _ps_escape_single_quotes(new_password)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$sec = ConvertTo-SecureString '{password_esc}' -AsPlainText -Force
$user = Get-ADUser -Identity '{username_esc}' -Server '{server_esc}' -ErrorAction Stop

Set-ADAccountPassword -Identity $user.DistinguishedName -Server '{server_esc}' -Reset -NewPassword $sec
Set-ADUser -Identity $user.DistinguishedName -Server '{server_esc}' -ChangePasswordAtLogon $true

$verify = Get-ADUser -Identity $user.DistinguishedName -Server '{server_esc}' -Properties pwdLastSet
Write-Output ("VERIFY pwdLastSet=" + $verify.pwdLastSet)
"""
    out = _run_ps(ps)

    if "VERIFY" not in out:
        raise ADServiceError(
            f"Password reset executed but no verification output returned. STDOUT={out}"
        )


def _move_user_via_winrm(cfg: ADConfig, username: str, target_ou_dn: str) -> str:
    username_esc = _ps_escape_single_quotes((username or "").strip())
    target_ou_esc = _ps_escape_single_quotes((target_ou_dn or "").strip())
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    if not username_esc:
        raise ADServiceError("Username is required.")
    if not target_ou_esc:
        raise ADServiceError("Target OU DN is required.")

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$user = Get-ADUser -Identity '{username_esc}' -Server '{server_esc}' -Properties DistinguishedName -ErrorAction Stop
Move-ADObject -Identity $user.DistinguishedName -TargetPath '{target_ou_esc}' -Server '{server_esc}'

$verify = Get-ADUser -Identity '{username_esc}' -Server '{server_esc}' -Properties DistinguishedName
Write-Output ("MOVED_DN=" + $verify.DistinguishedName)
"""
    out = _run_ps(ps)

    moved_dn = None
    for line in out.splitlines():
        if line.startswith("MOVED_DN="):
            moved_dn = line.split("=", 1)[1].strip()
            break

    if not moved_dn:
        raise ADServiceError(f"Move executed but verification output not returned. STDOUT={out}")

    return moved_dn


def create_user(
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password: str,
    phone: str = "",
    department: str = "",
    description: str = "",
    hr_id: str = "",
    target_ou_dn: Optional[str] = None,
    group_dns: Optional[Iterable[str]] = None,
    must_change_password: bool = False,
    user_cannot_change_password: bool = False,
    password_never_expires: bool = False,
    account_disabled: bool = False,
) -> str:
    cfg = _load_config()
    if cfg.safe_mode:
        return ""

    user_dn = _create_user_via_winrm(
        cfg=cfg,
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=password,
        phone=phone,
        department=department,
        description=description,
        hr_id=hr_id,
        target_ou_dn=target_ou_dn,
        must_change_password=must_change_password,
        user_cannot_change_password=user_cannot_change_password,
        password_never_expires=password_never_expires,
        account_disabled=account_disabled,
    )

    if group_dns:
        add_user_to_groups(user_dn, group_dns)

    return user_dn


def update_user(username: str, updates: dict) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return
    _update_user_via_winrm(cfg, username, updates)


def reset_user_password(username: str, new_password: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return
    _reset_password_via_winrm(cfg, username, new_password)


def lock_user(username: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return
    _set_user_account_disabled_via_winrm(cfg, username, True)


def unlock_user(username: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return
    _set_user_account_disabled_via_winrm(cfg, username, False)


def move_user(username: str, target_ou_dn: str) -> str:
    cfg = _load_config()
    if cfg.safe_mode:
        return ""

    valid_ou_dns = {ou["dn"] for ou in list_ous() if ou.get("dn")}
    if target_ou_dn not in valid_ou_dns:
        raise ADServiceError("Selected OU is invalid.")

    return _move_user_via_winrm(cfg, username, target_ou_dn)


# -----------------------------
# Group operations via WinRM
# -----------------------------

def create_group(
    group_name: str,
    description: str = "",
    members: Optional[Iterable[str]] = None,
) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    group_name_esc = _ps_escape_single_quotes(group_name)
    description_esc = _ps_escape_single_quotes(description)
    path_esc = _ps_escape_single_quotes(cfg.groups_ou_dn)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    member_items = []
    for m in members or []:
        value = str(m).strip()
        if value:
            member_items.append(f"'{_ps_escape_single_quotes(value)}'")
    members_block = ", ".join(member_items) if member_items else ""

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$existing = Get-ADGroup -LDAPFilter "(cn={group_name_esc})" -Server '{server_esc}' -ErrorAction SilentlyContinue
if ($existing) {{
    throw "Group already exists: $($existing.DistinguishedName)"
}}

$params = @{{
    Name           = '{group_name_esc}'
    SamAccountName = '{group_name_esc}'
    GroupScope     = 'Global'
    GroupCategory  = 'Security'
    Path           = '{path_esc}'
    Server         = '{server_esc}'
}}

if ('{description_esc}') {{ $params['Description'] = '{description_esc}' }}

New-ADGroup @params

$group = Get-ADGroup -Identity '{group_name_esc}' -Server '{server_esc}' -Properties DistinguishedName
if (-not $group) {{
    throw "Group creation succeeded but could not verify the created group."
}}

Write-Output ("CREATED_DN=" + $group.DistinguishedName)

if (@({members_block}).Count -gt 0) {{
    $resolvedMembers = @()
    foreach ($m in @({members_block})) {{
        $u = Get-ADUser -Identity $m -Server '{server_esc}' -ErrorAction SilentlyContinue
        if ($u) {{
            $resolvedMembers += $u.DistinguishedName
            continue
        }}

        $c = Get-ADComputer -Identity $m -Server '{server_esc}' -ErrorAction SilentlyContinue
        if ($c) {{
            $resolvedMembers += $c.DistinguishedName
            continue
        }}
    }}

    if ($resolvedMembers.Count -gt 0) {{
        Add-ADGroupMember -Identity $group.DistinguishedName -Members $resolvedMembers -Server '{server_esc}'
        Write-Output "MEMBERS_ADDED=1"
    }}
}}
"""
    out = _run_ps(ps)
    if "CREATED_DN=" not in out:
        raise ADServiceError(f"Group create executed but verification output not returned. STDOUT={out}")


def update_group(
    group_name: str,
    description: str = "",
    add_members: Optional[Iterable[str]] = None,
    remove_members: Optional[Iterable[str]] = None,
) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    group_name_esc = _ps_escape_single_quotes(group_name)
    description_esc = _ps_escape_single_quotes(description)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    add_items = [f"'{_ps_escape_single_quotes(str(m).strip())}'" for m in (add_members or []) if str(m).strip()]
    remove_items = [f"'{_ps_escape_single_quotes(str(m).strip())}'" for m in (remove_members or []) if str(m).strip()]
    add_block = ", ".join(add_items) if add_items else ""
    remove_block = ", ".join(remove_items) if remove_items else ""

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$group = Get-ADGroup -Identity '{group_name_esc}' -Server '{server_esc}' -ErrorAction Stop

if ('{description_esc}') {{
    Set-ADGroup -Identity $group.DistinguishedName -Server '{server_esc}' -Description '{description_esc}'
}}

foreach ($m in @({add_block})) {{
    if (-not $m) {{ continue }}

    $u = Get-ADUser -Identity $m -Server '{server_esc}' -ErrorAction SilentlyContinue
    if ($u) {{
        Add-ADGroupMember -Identity $group.DistinguishedName -Members $u.DistinguishedName -Server '{server_esc}'
        continue
    }}

    $c = Get-ADComputer -Identity $m -Server '{server_esc}' -ErrorAction SilentlyContinue
    if ($c) {{
        Add-ADGroupMember -Identity $group.DistinguishedName -Members $c.DistinguishedName -Server '{server_esc}'
    }}
}}

foreach ($m in @({remove_block})) {{
    if (-not $m) {{ continue }}

    $u = Get-ADUser -Identity $m -Server '{server_esc}' -ErrorAction SilentlyContinue
    if ($u) {{
        Remove-ADGroupMember -Identity $group.DistinguishedName -Members $u.DistinguishedName -Server '{server_esc}' -Confirm:$false
        continue
    }}

    $c = Get-ADComputer -Identity $m -Server '{server_esc}' -ErrorAction SilentlyContinue
    if ($c) {{
        Remove-ADGroupMember -Identity $group.DistinguishedName -Members $c.DistinguishedName -Server '{server_esc}' -Confirm:$false
    }}
}}

Write-Output ("UPDATED_DN=" + $group.DistinguishedName)
"""
    out = _run_ps(ps)
    if "UPDATED_DN=" not in out:
        raise ADServiceError(f"Group update executed but verification output not returned. STDOUT={out}")


def delete_group(group_name: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    group_name_esc = _ps_escape_single_quotes(group_name)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$group = Get-ADGroup -Identity '{group_name_esc}' -Server '{server_esc}' -ErrorAction Stop
Remove-ADGroup -Identity $group.DistinguishedName -Server '{server_esc}' -Confirm:$false
Write-Output "DELETED=1"
"""
    out = _run_ps(ps)
    if "DELETED=1" not in out:
        raise ADServiceError(f"Group delete executed but verification output not returned. STDOUT={out}")


def move_group(group_name: str, target_ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    group_name_esc = _ps_escape_single_quotes(group_name)
    target_ou_esc = _ps_escape_single_quotes(target_ou_dn)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$group = Get-ADGroup -Identity '{group_name_esc}' -Server '{server_esc}' -Properties DistinguishedName -ErrorAction Stop
Move-ADObject -Identity $group.DistinguishedName -TargetPath '{target_ou_esc}' -Server '{server_esc}'
Write-Output "MOVED=1"
"""
    out = _run_ps(ps)
    if "MOVED=1" not in out:
        raise ADServiceError(f"Group move executed but verification output not returned. STDOUT={out}")


def add_group_members(group_name: str, members: Iterable[str]) -> None:
    update_group(group_name=group_name, add_members=members)


def remove_group_members(group_name: str, members: Iterable[str]) -> None:
    update_group(group_name=group_name, remove_members=members)


def add_user_to_groups(user_dn: str, group_dns: Iterable[str]) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    user_dn_esc = _ps_escape_single_quotes(user_dn)
    server_esc = _ps_escape_single_quotes(cfg.server_name)
    group_items = [f"'{_ps_escape_single_quotes(str(g).strip())}'" for g in group_dns if str(g).strip()]
    group_block = ", ".join(group_items)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$userDn = '{user_dn_esc}'
foreach ($groupDn in @({group_block})) {{
    if (-not $groupDn) {{ continue }}
    Add-ADGroupMember -Identity $groupDn -Members $userDn -Server '{server_esc}'
}}
Write-Output "GROUPS_DONE=1"
"""
    out = _run_ps(ps)
    if "GROUPS_DONE=1" not in out:
        raise ADServiceError(f"Group membership update executed but verification output not returned. STDOUT={out}")


# -----------------------------
# Computer operations via WinRM
# -----------------------------

def create_computer(computer_name: str, ou_dn: Optional[str] = None, description: str = "") -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    name = (computer_name or "").strip()
    if not name:
        raise ADServiceError("Computer name is required.")

    target_ou = (ou_dn or "").strip() or cfg.computers_ou_dn
    if not target_ou:
        raise ADServiceError("Target OU DN is required.")

    name_esc = _ps_escape_single_quotes(name)
    ou_esc = _ps_escape_single_quotes(target_ou)
    desc_esc = _ps_escape_single_quotes(description)
    sam_esc = _ps_escape_single_quotes(_normalize_computer_sam(name))
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$existing = Get-ADComputer -Identity '{name_esc}' -Server '{server_esc}' -ErrorAction SilentlyContinue
if ($existing) {{
    throw "Computer already exists: $($existing.DistinguishedName)"
}}

$params = @{{
    Name           = '{name_esc}'
    SamAccountName = '{sam_esc}'
    Path           = '{ou_esc}'
    Server         = '{server_esc}'
}}

if ('{desc_esc}') {{ $params['Description'] = '{desc_esc}' }}

New-ADComputer @params

$verify = Get-ADComputer -Identity '{name_esc}' -Server '{server_esc}' -Properties DistinguishedName
Write-Output ("CREATED_DN=" + $verify.DistinguishedName)
"""
    out = _run_ps(ps)
    if "CREATED_DN=" not in out:
        raise ADServiceError(f"Computer create executed but verification output not returned. STDOUT={out}")


def lock_computer(computer_name: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    name_esc = _ps_escape_single_quotes(computer_name)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$computer = Get-ADComputer -Identity '{name_esc}' -Server '{server_esc}' -ErrorAction Stop
Disable-ADAccount -Identity $computer.DistinguishedName -Server '{server_esc}'
Write-Output "LOCKED=1"
"""
    out = _run_ps(ps)
    if "LOCKED=1" not in out:
        raise ADServiceError(f"Computer lock executed but verification output not returned. STDOUT={out}")


def unlock_computer(computer_name: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    name_esc = _ps_escape_single_quotes(computer_name)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$computer = Get-ADComputer -Identity '{name_esc}' -Server '{server_esc}' -ErrorAction Stop
Enable-ADAccount -Identity $computer.DistinguishedName -Server '{server_esc}'
Write-Output "UNLOCKED=1"
"""
    out = _run_ps(ps)
    if "UNLOCKED=1" not in out:
        raise ADServiceError(f"Computer unlock executed but verification output not returned. STDOUT={out}")


def move_computer(computer_name: str, target_ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    name_esc = _ps_escape_single_quotes(computer_name)
    target_ou_esc = _ps_escape_single_quotes(target_ou_dn)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$computer = Get-ADComputer -Identity '{name_esc}' -Server '{server_esc}' -Properties DistinguishedName -ErrorAction Stop
Move-ADObject -Identity $computer.DistinguishedName -TargetPath '{target_ou_esc}' -Server '{server_esc}'
Write-Output "MOVED=1"
"""
    out = _run_ps(ps)
    if "MOVED=1" not in out:
        raise ADServiceError(f"Computer move executed but verification output not returned. STDOUT={out}")


def update_computer(computer_name: str, updates: dict) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    name_esc = _ps_escape_single_quotes(computer_name)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    clean_updates = {}
    for key, value in (updates or {}).items():
        if value is None or value == "":
            continue
        clean_updates[key] = _ps_escape_single_quotes(value)

    if not clean_updates:
        return

    replace_lines = []
    for key, value in clean_updates.items():
        replace_lines.append(f"$replace['{key}'] = '{value}'")
    replace_block = "\n".join(replace_lines)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$computer = Get-ADComputer -Identity '{name_esc}' -Server '{server_esc}' -ErrorAction Stop
$replace = @{{}}
{replace_block}

Set-ADComputer -Identity $computer.DistinguishedName -Server '{server_esc}' -Replace $replace
Write-Output "UPDATED=1"
"""
    out = _run_ps(ps)
    if "UPDATED=1" not in out:
        raise ADServiceError(f"Computer update executed but verification output not returned. STDOUT={out}")


# -----------------------------
# OU operations via WinRM
# -----------------------------

def create_ou(ou_name: str, parent_dn: str, description: str = "", protect: bool = False) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    ou_name_esc = _ps_escape_single_quotes(ou_name)
    parent_esc = _ps_escape_single_quotes(parent_dn or cfg.base_dn)
    description_esc = _ps_escape_single_quotes(description)
    server_esc = _ps_escape_single_quotes(cfg.server_name)
    ps_protect = "$true" if protect else "$false"

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$params = @{{
    Name   = '{ou_name_esc}'
    Path   = '{parent_esc}'
    Server = '{server_esc}'
}}

if ('{description_esc}') {{ $params['Description'] = '{description_esc}' }}
$params['ProtectedFromAccidentalDeletion'] = {ps_protect}

New-ADOrganizationalUnit @params
Write-Output "CREATED=1"
"""
    out = _run_ps(ps)
    if "CREATED=1" not in out:
        raise ADServiceError(f"OU create executed but verification output not returned. STDOUT={out}")


def update_ou(ou_dn: str, new_name: str = "", description: str = "", protect: bool = False) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    ou_dn_esc = _ps_escape_single_quotes(ou_dn)
    new_name_esc = _ps_escape_single_quotes(new_name)
    description_esc = _ps_escape_single_quotes(description)
    server_esc = _ps_escape_single_quotes(cfg.server_name)
    ps_protect = "$true" if protect else "$false"

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$targetDn = '{ou_dn_esc}'

if ('{new_name_esc}') {{
    Rename-ADObject -Identity $targetDn -NewName '{new_name_esc}' -Server '{server_esc}'
    $obj = Get-ADObject -Identity $targetDn -Server '{server_esc}' -Properties DistinguishedName
    $parentDn = $obj.DistinguishedName.Split(',', 2)[1]
    $targetDn = "OU={new_name_esc}," + $parentDn
}}

if ('{description_esc}') {{
    Set-ADOrganizationalUnit -Identity $targetDn -Server '{server_esc}' -Description '{description_esc}'
}}

Set-ADOrganizationalUnit -Identity $targetDn -Server '{server_esc}' -ProtectedFromAccidentalDeletion {ps_protect}
Write-Output ("UPDATED_DN=" + $targetDn)
"""
    out = _run_ps(ps)
    if "UPDATED_DN=" not in out:
        raise ADServiceError(f"OU update executed but verification output not returned. STDOUT={out}")


def delete_ou(ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    ou_dn_esc = _ps_escape_single_quotes(ou_dn)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Set-ADOrganizationalUnit -Identity '{ou_dn_esc}' -Server '{server_esc}' -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
Remove-ADOrganizationalUnit -Identity '{ou_dn_esc}' -Server '{server_esc}' -Recursive -Confirm:$false
Write-Output "DELETED=1"
"""
    out = _run_ps(ps)
    if "DELETED=1" not in out:
        raise ADServiceError(f"OU delete executed but verification output not returned. STDOUT={out}")


def move_ou(ou_dn: str, target_parent_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    ou_dn_esc = _ps_escape_single_quotes(ou_dn)
    target_parent_esc = _ps_escape_single_quotes(target_parent_dn)
    server_esc = _ps_escape_single_quotes(cfg.server_name)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Move-ADObject -Identity '{ou_dn_esc}' -TargetPath '{target_parent_esc}' -Server '{server_esc}'
Write-Output "MOVED=1"
"""
    out = _run_ps(ps)
    if "MOVED=1" not in out:
        raise ADServiceError(f"OU move executed but verification output not returned. STDOUT={out}")


# -----------------------------
# LDAP read-only operations
# -----------------------------

def get_ad_counts() -> dict:
    cfg = _load_config()
    conn = _connect(cfg)
    try:
        def _count(filter_str: str) -> int:
            entries = conn.extend.standard.paged_search(
                search_base=cfg.base_dn,
                search_filter=filter_str,
                search_scope=SUBTREE,
                attributes=["distinguishedName"],
                paged_size=1000,
                generator=False,
            )
            return len(entries)

        return {
            "users": _count("(&(objectClass=user)(!(objectClass=computer)))"),
            "computers": _count("(objectClass=computer)"),
            "groups": _count("(objectClass=group)"),
            "ous": _count("(objectClass=organizationalUnit)"),
        }
    finally:
        conn.unbind()


def list_users(limit: int = 200) -> List[dict]:
    cfg = _load_config()
    conn = _connect(cfg)
    try:
        conn.search(
            cfg.base_dn,
            "(&(objectClass=user)(!(objectClass=computer)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "displayName", "mail", "employeeID"],
            size_limit=limit,
        )
        return [
            {
                "username": str(e.sAMAccountName.value) if "sAMAccountName" in e else "",
                "display_name": str(e.displayName.value) if "displayName" in e else "",
                "email": str(e.mail.value) if "mail" in e else "",
                "hr_id": str(e.employeeID.value) if "employeeID" in e else "",
            }
            for e in conn.entries
        ]
    finally:
        conn.unbind()


def list_computers(limit: int = 200) -> List[dict]:
    cfg = _load_config()
    conn = _connect(cfg)
    try:
        conn.search(
            cfg.base_dn,
            "(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "cn"],
            size_limit=limit,
        )
        return [
            {
                "name": str(e.cn.value) if "cn" in e else "",
                "sam": str(e.sAMAccountName.value) if "sAMAccountName" in e else "",
            }
            for e in conn.entries
        ]
    finally:
        conn.unbind()


def list_groups(limit: int = 5000) -> List[dict]:
    cfg = _load_config()
    conn = _connect(cfg)
    try:
        base = _resolve_base_dn(conn, cfg)
        conn.search(
            base,
            "(objectClass=group)",
            search_scope=SUBTREE,
            attributes=["cn", "description", "distinguishedName"],
            size_limit=limit,
        )
        return [
            {
                "name": str(e.cn.value) if "cn" in e else "",
                "description": str(e.description.value) if "description" in e else "",
                "dn": str(e.distinguishedName.value) if "distinguishedName" in e else "",
            }
            for e in conn.entries
        ]
    finally:
        conn.unbind()


def list_ous(limit: int = 2000) -> List[dict]:
    cfg = _load_config()
    conn = _connect(cfg)
    try:
        base = _resolve_base_dn(conn, cfg)
        conn.search(
            base,
            "(|(objectClass=organizationalUnit)(objectClass=container))",
            search_scope=SUBTREE,
            attributes=["ou", "cn", "distinguishedName"],
            size_limit=limit,
        )

        out = []
        for e in conn.entries:
            dn = str(e.distinguishedName.value) if "distinguishedName" in e else ""
            name = (
                (str(e.ou.value) if "ou" in e else "")
                or (str(e.cn.value) if "cn" in e else "")
                or dn
            )
            out.append({"ou": name, "dn": dn})

        out.sort(key=lambda x: (x["ou"] or "").lower())
        return out
    finally:
        conn.unbind()
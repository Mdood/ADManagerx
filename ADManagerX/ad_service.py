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
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
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

    conn = Connection(server, user=bind_user, password=cfg.bind_password, auto_bind=True)
    return conn


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
    target_ou_dn: Optional[str] = None,
    must_change_password: bool = False,
    user_cannot_change_password: bool = False,
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

New-ADUser @params

$created = Get-ADUser -Identity $username -Server $server -Properties DistinguishedName,Enabled,pwdLastSet
if (-not $created) {{
    throw "User creation succeeded but could not verify the created user."
}}

Write-Output ("CREATED_DN=" + $created.DistinguishedName)
Write-Output ("VERIFY Enabled=" + $created.Enabled + " pwdLastSet=" + $created.pwdLastSet)
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


def _set_password_via_winrm(user_dn: str, password: str, server: str) -> None:
    dn = _ps_escape_single_quotes(user_dn)
    pw = _ps_escape_single_quotes(password)
    srv = _ps_escape_single_quotes(server)

    ps = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$sec = ConvertTo-SecureString '{pw}' -AsPlainText -Force

Set-ADAccountPassword -Identity '{dn}' -Server '{srv}' -Reset -NewPassword $sec
Enable-ADAccount -Identity '{dn}' -Server '{srv}'
Set-ADUser -Identity '{dn}' -Server '{srv}' -ChangePasswordAtLogon $true

$u = Get-ADUser -Identity '{dn}' -Server '{srv}' -Properties pwdLastSet,Enabled
Write-Output "VERIFY Enabled=$($u.Enabled) pwdLastSet=$($u.pwdLastSet)"
"""
    out = _run_ps(ps)

    if "VERIFY" not in out:
        raise ADServiceError(f"WinRM executed but no verification output returned. STDOUT={out}")


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


def _set_account_disabled(conn: Connection, dn: str, disabled: bool) -> None:
    conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["userAccountControl"])
    if not conn.entries:
        raise ADServiceError("Account not found for UAC update.")

    uac = int(conn.entries[0]["userAccountControl"].value)
    if disabled:
        new_uac = uac | 0x2
    else:
        new_uac = uac & ~0x2

    conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
    if conn.result["description"] != "success":
        raise ADServiceError(conn.result.get("message", "Failed to update account status."))


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


def create_user(
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password: str,
    phone: str = "",
    department: str = "",
    description: str = "",
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
        target_ou_dn=target_ou_dn,
        must_change_password=must_change_password,
        user_cannot_change_password=user_cannot_change_password,
        password_never_expires=password_never_expires,
        account_disabled=account_disabled,
    )

    if group_dns:
        conn = _connect(cfg)
        try:
            for group_dn in group_dns:
                group_dn = (group_dn or "").strip()
                if not group_dn:
                    continue

                conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
                if conn.result["description"] != "success":
                    raise ADServiceError(
                        conn.result.get("message", f"Failed adding user to group: {group_dn}")
                    )
        finally:
            conn.unbind()

    return user_dn


def add_user_to_groups(user_dn: str, group_dns: Iterable[str]) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        for group_dn in group_dns:
            group_dn = (group_dn or "").strip()
            if not group_dn:
                continue

            conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
            if conn.result["description"] != "success":
                raise ADServiceError(conn.result.get("message", f"Failed adding to group {group_dn}"))
    finally:
        conn.unbind()


def reset_user_password(username: str, new_password: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    _reset_password_via_winrm(cfg, username, new_password)


def lock_user(username: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_user_dn(conn, cfg, username)
        if not dn:
            raise ADServiceError("User not found.")
        _set_account_disabled(conn, dn, True)
    finally:
        conn.unbind()


def unlock_user(username: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_user_dn(conn, cfg, username)
        if not dn:
            raise ADServiceError("User not found.")
        _set_account_disabled(conn, dn, False)
    finally:
        conn.unbind()


def move_user(username: str, target_ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_user_dn(conn, cfg, username)
        if not dn:
            raise ADServiceError("User not found.")
        rdn = dn.split(",", 1)[0]
        conn.modify_dn(dn, rdn, new_superior=target_ou_dn)
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to move user."))
    finally:
        conn.unbind()


def update_user(username: str, updates: dict) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_user_dn(conn, cfg, username)
        if not dn:
            raise ADServiceError("User not found.")

        changes = {}
        for key, value in updates.items():
            if value is None or value == "":
                continue
            changes[key] = [(MODIFY_REPLACE, [value])]

        if not changes:
            return

        conn.modify(dn, changes)
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to update user."))
    finally:
        conn.unbind()


def create_computer(computer_name: str, ou_dn: Optional[str] = None, description: str = "") -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        sam = _normalize_computer_sam(computer_name)
        target_ou = ou_dn or cfg.computers_ou_dn
        dn = f"CN={computer_name},{target_ou}"
        attrs = {
            "objectClass": ["top", "computer"],
            "sAMAccountName": sam,
        }
        if description:
            attrs["description"] = description

        if not conn.add(dn, attributes=attrs):
            raise ADServiceError(conn.result.get("message", "Failed to create computer."))
    finally:
        conn.unbind()


def lock_computer(computer_name: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_computer_dn(conn, cfg, computer_name)
        if not dn:
            raise ADServiceError("Computer not found.")
        _set_account_disabled(conn, dn, True)
    finally:
        conn.unbind()


def unlock_computer(computer_name: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_computer_dn(conn, cfg, computer_name)
        if not dn:
            raise ADServiceError("Computer not found.")
        _set_account_disabled(conn, dn, False)
    finally:
        conn.unbind()


def move_computer(computer_name: str, target_ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_computer_dn(conn, cfg, computer_name)
        if not dn:
            raise ADServiceError("Computer not found.")
        rdn = dn.split(",", 1)[0]
        conn.modify_dn(dn, rdn, new_superior=target_ou_dn)
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to move computer."))
    finally:
        conn.unbind()


def update_computer(computer_name: str, updates: dict) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_computer_dn(conn, cfg, computer_name)
        if not dn:
            raise ADServiceError("Computer not found.")

        changes = {}
        for key, value in updates.items():
            if value is None or value == "":
                continue
            changes[key] = [(MODIFY_REPLACE, [value])]

        if not changes:
            return

        conn.modify(dn, changes)
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to update computer."))
    finally:
        conn.unbind()


def create_group(
    group_name: str,
    description: str = "",
    members: Optional[Iterable[str]] = None,
) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = f"CN={group_name},{cfg.groups_ou_dn}"
        attrs = {
            "objectClass": ["top", "group"],
            "sAMAccountName": group_name,
            "cn": group_name,
            "groupType": -2147483646,
        }
        if description:
            attrs["description"] = description

        if not conn.add(dn, attributes=attrs):
            raise ADServiceError(conn.result.get("message", "Failed to create group."))

        if members:
            member_dns = []
            for m in members:
                dn_m = _get_user_dn(conn, cfg, m) or _get_computer_dn(conn, cfg, m)
                if dn_m:
                    member_dns.append(dn_m)

            if member_dns:
                conn.modify(dn, {"member": [(MODIFY_ADD, member_dns)]})
                if conn.result["description"] != "success":
                    raise ADServiceError(conn.result.get("message", "Failed to add initial members."))
    finally:
        conn.unbind()


def update_group(
    group_name: str,
    description: str = "",
    add_members: Optional[Iterable[str]] = None,
    remove_members: Optional[Iterable[str]] = None,
) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_group_dn(conn, cfg, group_name)
        if not dn:
            raise ADServiceError("Group not found.")

        if description:
            conn.modify(dn, {"description": [(MODIFY_REPLACE, [description])]})
            if conn.result["description"] != "success":
                raise ADServiceError(conn.result.get("message", "Failed to update group description."))

        add_members = add_members or []
        remove_members = remove_members or []

        if add_members:
            member_dns = []
            for m in add_members:
                dn_m = _get_user_dn(conn, cfg, m) or _get_computer_dn(conn, cfg, m)
                if dn_m:
                    member_dns.append(dn_m)

            if member_dns:
                conn.modify(dn, {"member": [(MODIFY_ADD, member_dns)]})
                if conn.result["description"] != "success":
                    raise ADServiceError(conn.result.get("message", "Failed adding group members."))

        if remove_members:
            member_dns = []
            for m in remove_members:
                dn_m = _get_user_dn(conn, cfg, m) or _get_computer_dn(conn, cfg, m)
                if dn_m:
                    member_dns.append(dn_m)

            if member_dns:
                conn.modify(dn, {"member": [(MODIFY_DELETE, member_dns)]})
                if conn.result["description"] != "success":
                    raise ADServiceError(conn.result.get("message", "Failed removing group members."))
    finally:
        conn.unbind()


def delete_group(group_name: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_group_dn(conn, cfg, group_name)
        if not dn:
            raise ADServiceError("Group not found.")

        if not conn.delete(dn):
            raise ADServiceError(conn.result.get("message", "Failed to delete group."))
    finally:
        conn.unbind()


def move_group(group_name: str, target_ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_group_dn(conn, cfg, group_name)
        if not dn:
            raise ADServiceError("Group not found.")

        rdn = dn.split(",", 1)[0]
        conn.modify_dn(dn, rdn, new_superior=target_ou_dn)
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to move group."))
    finally:
        conn.unbind()


def add_group_members(group_name: str, members: Iterable[str]) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_group_dn(conn, cfg, group_name)
        if not dn:
            raise ADServiceError("Group not found.")

        member_dns = []
        for m in members:
            dn_m = _get_user_dn(conn, cfg, m) or _get_computer_dn(conn, cfg, m)
            if dn_m:
                member_dns.append(dn_m)

        if member_dns:
            conn.modify(dn, {"member": [(MODIFY_ADD, member_dns)]})
            if conn.result["description"] != "success":
                raise ADServiceError(conn.result.get("message", "Failed adding group members."))
    finally:
        conn.unbind()


def remove_group_members(group_name: str, members: Iterable[str]) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = _get_group_dn(conn, cfg, group_name)
        if not dn:
            raise ADServiceError("Group not found.")

        member_dns = []
        for m in members:
            dn_m = _get_user_dn(conn, cfg, m) or _get_computer_dn(conn, cfg, m)
            if dn_m:
                member_dns.append(dn_m)

        if member_dns:
            conn.modify(dn, {"member": [(MODIFY_DELETE, member_dns)]})
            if conn.result["description"] != "success":
                raise ADServiceError(conn.result.get("message", "Failed removing group members."))
    finally:
        conn.unbind()


def create_ou(ou_name: str, parent_dn: str, description: str = "", protect: bool = False) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        dn = f"OU={ou_name},{parent_dn or cfg.base_dn}"
        attrs = {"objectClass": ["top", "organizationalUnit"]}
        if description:
            attrs["description"] = description

        if not conn.add(dn, attributes=attrs):
            raise ADServiceError(conn.result.get("message", "Failed to create OU."))

        if protect:
            pass
    finally:
        conn.unbind()


def update_ou(ou_dn: str, new_name: str = "", description: str = "", protect: bool = False) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        current_dn = ou_dn

        if new_name:
            conn.modify_dn(ou_dn, f"OU={new_name}")
            if conn.result["description"] != "success":
                raise ADServiceError(conn.result.get("message", "Failed to rename OU."))

            parent = ou_dn.split(",", 1)[1] if "," in ou_dn else ""
            current_dn = f"OU={new_name},{parent}" if parent else f"OU={new_name}"

        if description:
            conn.modify(current_dn, {"description": [(MODIFY_REPLACE, [description])]})
            if conn.result["description"] != "success":
                raise ADServiceError(conn.result.get("message", "Failed to update OU description."))

        if protect:
            pass
    finally:
        conn.unbind()


def delete_ou(ou_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        if not conn.delete(ou_dn):
            raise ADServiceError(conn.result.get("message", "Failed to delete OU."))
    finally:
        conn.unbind()


def move_ou(ou_dn: str, target_parent_dn: str) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return

    conn = _connect(cfg)
    try:
        rdn = ou_dn.split(",", 1)[0]
        conn.modify_dn(ou_dn, rdn, new_superior=target_parent_dn)
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to move OU."))
    finally:
        conn.unbind()


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
            attributes=["sAMAccountName", "displayName", "mail"],
            size_limit=limit,
        )
        return [
            {
                "username": str(e.sAMAccountName.value) if "sAMAccountName" in e else "",
                "display_name": str(e.displayName.value) if "displayName" in e else "",
                "email": str(e.mail.value) if "mail" in e else "",
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
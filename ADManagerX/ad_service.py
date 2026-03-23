from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

from ldap3 import Connection, Server, ALL, ALL_ATTRIBUTES, BASE, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, Tls
import ssl

from .models import LdapSettings

import winrm


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

    # init winrm session using the DB instance values (strings)
    bind_user = cfg_db.bind_dn
    if "@" not in bind_user:
        bind_user = f"{bind_user}@{cfg_db.upn_suffix}"

    session = winrm.Session(
        cfg_db.server_name,  # ✅ instance value, not field
        auth=(bind_user, cfg_db.bind_password),
        transport="ntlm"
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
        server_name=cfg_db.server_name or "",  # ✅
    )


def _connect(cfg: ADConfig) -> Connection:
    tls = Tls(validate=ssl.CERT_NONE) if cfg.use_ssl else None
    server = Server(cfg.server_uri, use_ssl=cfg.use_ssl, get_info=ALL, tls=tls)
    conn = Connection(server, user=cfg.bind_dn, password=cfg.bind_password, auto_bind=True)
    
    return conn



def _search_one(conn: Connection, base_dn: str, search_filter: str, attributes: Optional[List[str]] = None):
    attrs = attributes or ALL_ATTRIBUTES
    ok = conn.search(base_dn, search_filter, search_scope=SUBTREE, attributes=attrs, size_limit=1)
    if not ok or not conn.entries:
        return None
    return conn.entries[0]


def _ps_escape_single_quotes(val) -> str:
    return str(val).replace("'", "''")


def _set_password_via_winrm(user_dn: str, password: str, server: str) -> None:
    global session
    if session is None:
        raise ADServiceError("WinRM session not initialized. Check _load_config().")

    dn = _ps_escape_single_quotes(user_dn)
    pw = _ps_escape_single_quotes(password)
    srv = _ps_escape_single_quotes(server)

    ps = f"""
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory

    $sec = ConvertTo-SecureString '{pw}' -AsPlainText -Force

    # Use DN (exact object) + specify server to avoid ambiguity/replication delay
    Set-ADAccountPassword -Identity '{dn}' -Server '{srv}' -Reset -NewPassword $sec
    Enable-ADAccount -Identity '{dn}' -Server '{srv}'
    Set-ADUser -Identity '{dn}' -Server '{srv}' -ChangePasswordAtLogon $true

    # Verify password was set by reading a couple fields
    $u = Get-ADUser -Identity '{dn}' -Server '{srv}' -Properties pwdLastSet,Enabled
    "VERIFY Enabled=$($u.Enabled) pwdLastSet=$($u.pwdLastSet)"
    """

    r = session.run_ps(ps)

    out = (r.std_out or b"").decode(errors="ignore")
    err = (r.std_err or b"").decode(errors="ignore")

    if r.status_code != 0:
        raise ADServiceError(f"WinRM password set failed (status={r.status_code}). STDERR={err} STDOUT={out}")

    # Optional: if you want to *ensure* verification line exists
    if "VERIFY" not in out:
        raise ADServiceError(f"WinRM executed but no verification output returned. STDOUT={out} STDERR={err}")
    

def _username_to_upn(username: str, upn_suffix: str) -> str:
    if "@" in username:
        return username
    return f"{username}@{upn_suffix}"


def _normalize_computer_sam(name: str) -> str:
    return name if name.endswith("$") else f"{name}$"


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
    if not conn.result["description"] == "success":
        raise ADServiceError(conn.result.get("message", "Failed to update account status."))


def test_connection() -> None:
    cfg = _load_config()
    conn = _connect(cfg)
    conn.unbind()

def _resolve_base_dn(conn: Connection, cfg: ADConfig) -> str:
    # If base_dn works, keep it.
    if (cfg.base_dn or "").strip():
        return cfg.base_dn.strip()

    # Otherwise read RootDSE defaultNamingContext
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
) -> str:
    cfg = _load_config()
    if cfg.safe_mode:
        return ""

    conn = _connect(cfg)
    try:
        username = (username or "").strip()
        if not username:
            raise ADServiceError("Username is required.")

        if not password:
            raise ADServiceError("Password is required.")

        ou_dn = (target_ou_dn or "").strip() or cfg.users_ou_dn
        if not ou_dn:
            raise ADServiceError("Target OU DN is empty and no default Users OU DN is configured.")

        # 1) Pre-check: does username already exist anywhere?
        flt = cfg.user_search_filter.format(username=username)
        conn.search(cfg.base_dn, flt, search_scope=SUBTREE, attributes=["distinguishedName"], size_limit=1)
        if conn.entries:
            existing_dn = conn.entries[0].entry_dn
            raise ADServiceError(f"User already exists: {existing_dn}")

        # 2) Create with CN=username (unique)
        user_dn = f"CN={username},{ou_dn}"
        display_name = f"{first_name} {last_name}".strip() or username

        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": username,
            "userPrincipalName": _username_to_upn(username, cfg.upn_suffix),
            "givenName": first_name or username,
            "sn": last_name or username,
            "displayName": display_name,
            "mail": email,
        }
        if phone:
            attrs["telephoneNumber"] = phone
        if department:
            attrs["department"] = department
        if description:
            attrs["description"] = description

        if not conn.add(user_dn, attributes=attrs):
            raise ADServiceError(conn.result.get("message", "Failed to create user."))

        # 3) Set password + enable via WinRM (PowerShell)
        try:
            _set_password_via_winrm(user_dn=user_dn, password=password, server=cfg.server_name)
        except Exception as exc:
            # cleanup to avoid leaving half-created object
            try:
                conn.delete(user_dn)
            except Exception:
                pass
            raise

        # 4) Ensure enabled in LDAP too (optional but fine)
        conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
        if conn.result["description"] != "success":
            raise ADServiceError(conn.result.get("message", "Failed to enable user account (LDAP)."))

        # 5) Add to selected groups (DNs)
        if group_dns:
            for group_dn in group_dns:
                group_dn = (group_dn or "").strip()
                if not group_dn:
                    continue
                conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
                if conn.result["description"] != "success":
                    raise ADServiceError(conn.result.get("message", f"Failed adding user to group: {group_dn}"))

        return user_dn

    finally:
        conn.unbind()

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
    conn = _connect(cfg)
    try:
        dn = _get_user_dn(conn, cfg, username)
        if not dn:
            raise ADServiceError("User not found.")
        try:
            conn.extend.microsoft.modify_password(dn, new_password)
        except Exception as exc:
            raise ADServiceError(f"Failed to reset password. Ensure LDAPS is enabled. {exc}") from exc
    finally:
        conn.unbind()


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


def create_group(group_name: str, description: str = "", members: Optional[Iterable[str]] = None) -> None:
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
            "groupType": -2147483646,  # Global Security Group
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
    finally:
        conn.unbind()


def update_group(group_name: str, description: str = "", add_members: Optional[Iterable[str]] = None, remove_members: Optional[Iterable[str]] = None) -> None:
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
        if remove_members:
            member_dns = []
            for m in remove_members:
                dn_m = _get_user_dn(conn, cfg, m) or _get_computer_dn(conn, cfg, m)
                if dn_m:
                    member_dns.append(dn_m)
            if member_dns:
                conn.modify(dn, {"member": [(MODIFY_DELETE, member_dns)]})
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
            # Protection from accidental deletion is done via security descriptor; skip for now
            pass
    finally:
        conn.unbind()


def update_ou(ou_dn: str, new_name: str = "", description: str = "", protect: bool = False) -> None:
    cfg = _load_config()
    if cfg.safe_mode:
        return
    conn = _connect(cfg)
    try:
        if new_name:
            conn.modify_dn(ou_dn, f"OU={new_name}")
        if description:
            conn.modify(ou_dn, {"description": [(MODIFY_REPLACE, [description])]})
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
            name = (str(e.ou.value) if "ou" in e else "") or (str(e.cn.value) if "cn" in e else "") or dn
            out.append({"ou": name, "dn": dn})

        out.sort(key=lambda x: (x["ou"] or "").lower())
        return out
    finally:
        conn.unbind()


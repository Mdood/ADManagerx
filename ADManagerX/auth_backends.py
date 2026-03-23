from typing import Optional
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, Tls, BASE
import ssl

from .models import LdapSettings


class DBLDAPBackend(BaseBackend):
    """
    Authenticate against LDAP using settings stored in DB.
    """

    def authenticate(self, request, username: Optional[str] = None, password: Optional[str] = None, **kwargs):
        if not username or not password:
            return None

        cfg = LdapSettings.get_settings()
        if not cfg or not LdapSettings.is_configured():
            return None  # not configured => do not handle

        # Build server (with SSL if needed)
        tls = None
        if cfg.use_ssl:
            tls = Tls(validate=ssl.CERT_NONE)  # for internal AD; tighten in production

        server = Server(cfg.server_uri, use_ssl=cfg.use_ssl, get_info=ALL, tls=tls)

        # 1) Bind with service account (or anonymous) to find the user's DN
        try:
            conn = Connection(server, user=cfg.bind_dn or None, password=cfg.bind_password or None, auto_bind=True)
        except Exception:
            return None  # connection failure or bad bind DN/PW

        # 2) Resolve search base and search for user entry
        search_base = self._resolve_search_base(cfg, conn, server)
        if not search_base:
            conn.unbind()
            return None

        search_filter = cfg.user_search_filter.format(username=username)
        try:
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=ALL_ATTRIBUTES,
                size_limit=1
            )
        except Exception:
            conn.unbind()
            return None

        if len(conn.entries) == 0:
            conn.unbind()
            return None

        user_entry = conn.entries[0]
        user_dn = user_entry.entry_dn
        conn.unbind()

        # 3) Try binding as the actual user with the provided password
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        except Exception:
            return None  # invalid credentials

        user_conn.unbind()

        # 4) Success => get/create local user
        User = get_user_model()
        user_obj, _ = User.objects.get_or_create(username=username, defaults={
            "is_active": True
        })
        # Optionally pull attributes from LDAP to fill names/email
        # Example:
        # email = str(user_entry.mail) if 'mail' in user_entry else ''
        # user_obj.email = email or user_obj.email

        user_obj.save()
        return user_obj

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    @staticmethod
    def _resolve_search_base(cfg, conn, server):
        if cfg.user_search_base:
            return cfg.user_search_base

        # Try to pull default naming context from server info
        try:
            info = server.info
            if info and info.other and "defaultNamingContext" in info.other:
                return info.other["defaultNamingContext"][0]
        except Exception:
            pass

        # Fallback: query RootDSE
        try:
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["defaultNamingContext"],
                size_limit=1,
            )
            if conn.entries:
                entry = conn.entries[0]
                if "defaultNamingContext" in entry:
                    return str(entry["defaultNamingContext"][0])
        except Exception:
            return None

        return None

from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse
from .models import LdapSettings


class RequireLdapSetupMiddleware:
    """
    If LDAP settings are not configured, redirect all requests to the setup page,
    except for whitelisted prefixes (admin, static, setup itself, etc.).
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.exclusions = getattr(settings, 'LDAP_SETUP_EXCLUDE_PREFIXES', [
            '/admin/', '/static/', '/ldap/setup/', '/favicon.ico'
        ])

    def __call__(self, request):
        path = request.path

        # Allow excluded paths
        if any(path.startswith(p) for p in self.exclusions):
            return self.get_response(request)

        # If not configured, redirect to setup
        if not LdapSettings.is_configured():
            return redirect(reverse('ldap_setup'))

        return self.get_response(request)

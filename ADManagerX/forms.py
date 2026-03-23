from django import forms
from urllib.parse import urlparse
from .models import LdapSettings


class LdapSettingsForm(forms.ModelForm):
    server_ip = forms.CharField(
        required=False,
        label="Domain Controller IP",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "192.168.1.10"}),
    )
    server_name = forms.CharField(
        required=False,
        label="Domain Controller Name",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "DC01"}),
        help_text="Computer name of the domain controller (e.g., DC01).",
    )
    service_domain = forms.CharField(
        required=False,
        label="Domain",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "corp.local"}),
        help_text="Your AD domain (example: corp.local).",
    )
    service_username = forms.CharField(
        required=False,
        label="Service Account Username",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "svc_adm"}),
        help_text="Username only (no domain).",
    )
    base_dn = forms.CharField(
        required=False,
        label="Domain DN (Base DN)",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "DC=corp,DC=local"}),
        help_text="Root DN for your domain.",
    )
    users_ou_dn = forms.CharField(
        required=False,
        label="Default Users OU DN",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "OU=Users,DC=corp,DC=local"}),
    )
    computers_ou_dn = forms.CharField(
        required=False,
        label="Default Computers OU DN",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "OU=Computers,DC=corp,DC=local"}),
    )
    groups_ou_dn = forms.CharField(
        required=False,
        label="Default Groups OU DN",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "OU=Groups,DC=corp,DC=local"}),
    )
    upn_suffix = forms.CharField(
        required=False,
        label="UPN Suffix",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "corp.local"}),
        help_text="Used to build userPrincipalName (e.g., username@corp.local).",
    )
    safe_mode = forms.BooleanField(
        required=False,
        label="Safe mode (dry-run for bulk/critical actions)",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )

    class Meta:
        model = LdapSettings
        fields = [
            "server_uri",
            "server_name",
            "use_ssl",
            "bind_dn",
            "bind_password",
            "base_dn",
            "users_ou_dn",
            "computers_ou_dn",
            "groups_ou_dn",
            "upn_suffix",
            "safe_mode",
            "user_search_base",
            "user_search_filter",
            "user_domain",
        ]
        widgets = {
            "server_uri": forms.HiddenInput(),
            "use_ssl": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "bind_dn": forms.HiddenInput(),
            "bind_password": forms.PasswordInput(attrs={"class": "form-control"}, render_value=True),
            "user_search_base": forms.HiddenInput(),
            "user_search_filter": forms.HiddenInput(),
            "user_domain": forms.HiddenInput(),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        instance = kwargs.get("instance")
        self.fields["user_search_base"].required = False
        self.fields["user_search_filter"].required = False
        self.fields["user_domain"].required = False
        self.fields["server_uri"].required = False
        self.fields["bind_password"].label = "Service Account Password"
        self.fields["bind_password"].help_text = "Password for the service account above."

        if instance and instance.server_uri:
            parsed = urlparse(instance.server_uri)
            if parsed.hostname:
                self.fields["server_ip"].initial = parsed.hostname

        if instance and instance.server_name:
            self.fields["server_name"].initial = instance.server_name
        if instance and instance.user_search_filter:
            self.fields["user_search_filter"].initial = instance.user_search_filter
        if not self.fields["user_search_filter"].initial:
            self.fields["user_search_filter"].initial = "(sAMAccountName={username})"
        if instance and instance.user_domain:
            self.fields["service_domain"].initial = instance.user_domain
            if instance.bind_dn and "@" in instance.bind_dn:
                self.fields["service_username"].initial = instance.bind_dn.split("@", 1)[0]
        if instance and instance.base_dn:
            self.fields["base_dn"].initial = instance.base_dn
        if instance and instance.users_ou_dn:
            self.fields["users_ou_dn"].initial = instance.users_ou_dn
        if instance and instance.computers_ou_dn:
            self.fields["computers_ou_dn"].initial = instance.computers_ou_dn
        if instance and instance.groups_ou_dn:
            self.fields["groups_ou_dn"].initial = instance.groups_ou_dn
        if instance and instance.upn_suffix:
            self.fields["upn_suffix"].initial = instance.upn_suffix
        if instance is not None:
            self.fields["safe_mode"].initial = bool(instance.safe_mode)

    def clean_user_search_filter(self):
        value = (self.cleaned_data.get("user_search_filter") or "").strip()
        if not value:
            return ""
        if "{username}" not in value:
            raise forms.ValidationError("Search filter must include {username}.")
        return value

    def clean(self):
        cleaned = super().clean()

        use_ssl = cleaned.get("use_ssl") or False
        server_ip = (cleaned.get("server_ip") or "").strip()
        service_domain = (cleaned.get("service_domain") or "").strip()
        service_username = (cleaned.get("service_username") or "").strip()
        bind_password = (cleaned.get("bind_password") or "").strip()
        base_dn = (cleaned.get("base_dn") or "").strip()
        users_ou_dn = (cleaned.get("users_ou_dn") or "").strip()
        computers_ou_dn = (cleaned.get("computers_ou_dn") or "").strip()
        groups_ou_dn = (cleaned.get("groups_ou_dn") or "").strip()
        upn_suffix = (cleaned.get("upn_suffix") or "").strip()

        if not server_ip:
            self.add_error("server_ip", "Domain Controller IP is required.")
        if not service_domain:
            self.add_error("service_domain", "Domain is required.")
        if not service_username:
            self.add_error("service_username", "Service account username is required.")
        if not bind_password:
            self.add_error("bind_password", "Service account password is required.")
        if not base_dn:
            self.add_error("base_dn", "Domain DN is required.")
        if not users_ou_dn:
            self.add_error("users_ou_dn", "Default Users OU DN is required.")
        if not computers_ou_dn:
            self.add_error("computers_ou_dn", "Default Computers OU DN is required.")
        if not groups_ou_dn:
            self.add_error("groups_ou_dn", "Default Groups OU DN is required.")
        if not upn_suffix:
            self.add_error("upn_suffix", "UPN suffix is required.")

        scheme = "ldaps" if use_ssl else "ldap"
        port = 636 if use_ssl else 389
        if server_ip:
            cleaned["server_uri"] = f"{scheme}://{server_ip}:{port}"

        # Keep defaults if not provided; backend can auto-resolve base DN.
        if not (cleaned.get("user_search_filter") or "").strip():
            cleaned["user_search_filter"] = "(sAMAccountName={username})"
        if cleaned.get("user_search_base") is None:
            cleaned["user_search_base"] = ""
        if cleaned.get("user_domain") is None:
            cleaned["user_domain"] = ""
        if service_domain:
            cleaned["user_domain"] = service_domain
        if service_domain and service_username:
            cleaned["bind_dn"] = f"{service_username}@{service_domain}"
        if base_dn:
            cleaned["base_dn"] = base_dn
        if users_ou_dn:
            cleaned["users_ou_dn"] = users_ou_dn
        if computers_ou_dn:
            cleaned["computers_ou_dn"] = computers_ou_dn
        if groups_ou_dn:
            cleaned["groups_ou_dn"] = groups_ou_dn
        if upn_suffix:
            cleaned["upn_suffix"] = upn_suffix

        return cleaned

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.server_uri = self.cleaned_data.get("server_uri") or instance.server_uri
        instance.server_name = self.cleaned_data.get("server_name") or instance.server_name
        instance.base_dn = self.cleaned_data.get("base_dn") or instance.base_dn
        instance.users_ou_dn = self.cleaned_data.get("users_ou_dn") or instance.users_ou_dn
        instance.computers_ou_dn = self.cleaned_data.get("computers_ou_dn") or instance.computers_ou_dn
        instance.groups_ou_dn = self.cleaned_data.get("groups_ou_dn") or instance.groups_ou_dn
        instance.upn_suffix = self.cleaned_data.get("upn_suffix") or instance.upn_suffix
        instance.safe_mode = bool(self.cleaned_data.get("safe_mode"))
        instance.user_search_base = self.cleaned_data.get("user_search_base") or instance.user_search_base
        instance.bind_dn = self.cleaned_data.get("bind_dn") or ""
        if commit:
            instance.save()
        return instance

    @staticmethod
    def _domain_to_base_dn(domain: str) -> str:
        parts = [p.strip() for p in domain.split(".") if p.strip()]
        return ",".join([f"DC={p}" for p in parts])

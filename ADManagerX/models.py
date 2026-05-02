from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db.models.signals import post_save
from django.dispatch import receiver


# ----------------------------
# Custom User
# ----------------------------
class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        """Create and save a regular user with the given username and password."""
        if not username:
            raise ValueError("The Username field must be set")
        user = self.model(username=username, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        """Create and save a superuser with username and password only."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=50, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []  # No extra required fields

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.username


# ----------------------------
# Helpdesk profile / permissions JSON
# ----------------------------
class HelpdeskProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="helpdesk_profile",
    )
    role = models.CharField(max_length=32, default="custom")
    ou = models.CharField(max_length=255, blank=True, default="")
    scope = models.CharField(max_length=255, blank=True, default="")
    # Requires MySQL 5.7+/MariaDB 10.2.7+; otherwise change to TextField with JSON serialization.
    permissions = models.JSONField(default=dict)  # legacy/global permissions
    domain_permissions = models.JSONField(default=dict, blank=True)  # {"ldap_id": {"role":"helpdesk", "scope":"OU=...", "permissions": {...}}}

    def can(self, resource: str, action: str) -> bool:
        return action in (self.permissions or {}).get(resource, [])

    def __str__(self):
        return f"{self.user} ({self.role})"


# Optional: auto-create HelpdeskProfile on user creation
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def _create_helpdesk_profile(sender, instance, created, **kwargs):
    if created:
        HelpdeskProfile.objects.get_or_create(user=instance)


# ----------------------------
# LDAP Settings (singleton-style; first row used)
# ----------------------------
class LdapSettings(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    name = models.CharField(max_length=100, blank=True, default="")
    domain_name = models.CharField(max_length=255, blank=True, default="")
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)

    server_uri = models.CharField(max_length=255)                 # ldap://host:389 or ldaps://host:636
    server_name = models.CharField(max_length=255, blank=True, default="")  # e.g. DC01
    use_ssl = models.BooleanField(default=False)
    bind_dn = models.CharField(max_length=512, blank=True)        # service account DN (optional if anonymous bind)
    bind_password = models.CharField(max_length=512, blank=True)  # consider encrypting in production
    base_dn = models.CharField(max_length=512, blank=True, default="")          # e.g. DC=corp,DC=local
    users_ou_dn = models.CharField(max_length=512, blank=True, default="")       # e.g. OU=Users,DC=corp,DC=local
    computers_ou_dn = models.CharField(max_length=512, blank=True, default="")   # e.g. OU=Computers,DC=corp,DC=local
    groups_ou_dn = models.CharField(max_length=512, blank=True, default="")      # e.g. OU=Groups,DC=corp,DC=local
    upn_suffix = models.CharField(max_length=255, blank=True, default="")        # e.g. corp.local
    safe_mode = models.BooleanField(default=False)
    user_search_base = models.CharField(max_length=512, blank=True, default="")  # e.g. OU=Users,DC=corp,DC=local
    user_search_filter = models.CharField(
        max_length=255,
        default='(sAMAccountName={username})',
        help_text="Use {username} placeholder."
    )
    user_domain = models.CharField(
        max_length=255, blank=True,
        help_text="Optional domain for UPN logins, e.g. corp.local"
    )

    def __str__(self):
        label = self.name or self.domain_name or self.user_domain or self.server_uri
        return f"{label} ({self.server_uri})"

    def save(self, *args, **kwargs):
        if self.is_default:
            type(self).objects.exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)

    @classmethod
    def get_settings(cls, settings_id=None):
        if settings_id:
            obj = cls.objects.filter(pk=settings_id, is_active=True).first()
            if obj:
                return obj
        return cls.objects.filter(is_active=True, is_default=True).first() or cls.objects.filter(is_active=True).first() or cls.objects.first()

    @classmethod
    def available_settings(cls):
        return cls.objects.filter(is_active=True).order_by("name", "domain_name", "server_uri")

    @classmethod
    def is_configured(cls, settings_id=None) -> bool:
        obj = cls.get_settings(settings_id=settings_id)
        if not obj:
            return False
        # user_search_base can be empty; we'll auto-resolve to the default naming context
        return bool(
            obj.server_uri
            and obj.user_search_filter
            and obj.base_dn
            and obj.users_ou_dn
            and obj.computers_ou_dn
            and obj.groups_ou_dn
            and obj.bind_dn
            and obj.bind_password
        )


# ----------------------------
# Domain objects (avoid name clashes with django.contrib.auth.models.Group)
# ----------------------------
class Computer(models.Model):
    name = models.CharField(max_length=100, unique=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="computers",
    )
    status = models.CharField(
        max_length=50,
        choices=[('active', 'Active'), ('locked', 'Locked')],
        default='active'
    )

    def __str__(self):
        return self.name


class DirectoryGroup(models.Model):
    """
    App-level 'Group' concept for directory/grouping purposes.
    Named 'DirectoryGroup' to avoid clashing with auth.Group.
    """
    name = models.CharField(max_length=100, unique=True)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="directory_groups",
    )

    def __str__(self):
        return self.name


class OU(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class Report(models.Model):
    title = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    data = models.TextField()

    def __str__(self):
        return self.title

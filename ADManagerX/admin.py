# ADManagerX/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    CustomUser,
    HelpdeskProfile,
    LdapSettings,
    Computer,
    DirectoryGroup,  # renamed from Group to avoid clash with auth.Group
    OU,
    Report,
)


@admin.register(CustomUser)
class CustomUserAdmin(DjangoUserAdmin):
    model = CustomUser
    list_display = ("id", "username", "is_staff", "is_active", "date_joined")
    list_filter = ("is_staff", "is_superuser", "is_active", "groups")
    ordering = ("username",)
    search_fields = ("username",)

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "password1", "password2", "is_staff", "is_superuser", "is_active"),
        }),
    )


@admin.register(HelpdeskProfile)
class HelpdeskProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "ou", "scope")
    search_fields = ("user__username", "role", "ou", "scope")


@admin.register(LdapSettings)
class LdapSettingsAdmin(admin.ModelAdmin):
    list_display = ("server_uri", "use_ssl", "updated_at")
    readonly_fields = ("created_at", "updated_at")


@admin.register(Computer)
class ComputerAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "status")
    list_filter = ("status",)
    search_fields = ("name", "owner__username")


@admin.register(DirectoryGroup)
class DirectoryGroupAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)
    filter_horizontal = ("members",)


@admin.register(OU)
class OUAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("title", "created_at", "owner")
    search_fields = ("title", "owner__username")
    date_hierarchy = "created_at"

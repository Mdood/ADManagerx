from urllib import request

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods, require_POST
from .models import HelpdeskProfile
from django.contrib.auth.decorators import login_required
from ldap3 import Server, Connection, Tls, BASE, ALL
import ssl

from .forms import LdapSettingsForm
from .models import LdapSettings
from .ad_service import (
    ADServiceError,
    create_user,
    reset_user_password,
    lock_user,
    unlock_user,
    move_user,
    update_user,
    create_computer,
    lock_computer,
    unlock_computer,
    move_computer,
    update_computer,
    create_group,
    update_group,
    delete_group,
    move_group,
    create_ou,
    update_ou,
    delete_ou,
    move_ou as ad_move_ou,
    list_ous, list_groups
)


def _read_excel_rows(uploaded_file):
    try:
        from openpyxl import load_workbook
    except Exception as exc:
        raise ADServiceError("openpyxl is required for Excel uploads.") from exc

    wb = load_workbook(uploaded_file, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [str(h).strip().lower() if h is not None else "" for h in rows[0]]
    data = []
    for row in rows[1:]:
        if not any(row):
            continue
        item = {}
        for idx, value in enumerate(row):
            key = headers[idx] if idx < len(headers) else f"col_{idx}"
            if isinstance(value, str):
                item[key] = value.strip()
            else:
                item[key] = value
        data.append(item)
    return data

def index(request):
    context = {}
    try:
        from .ad_service import get_ad_counts
        context["ad_counts"] = get_ad_counts()
    except Exception:
        context["ad_counts"] = {"users": 0, "computers": 0, "groups": 0, "ous": 0}
    return render(request, 'index.html', context)

@require_http_methods(["GET", "POST"])
def ldap_setup(request):
    """
    First-run LDAP setup page. Lets user enter settings, test, and save.
    """
    instance = LdapSettings.get_settings()
    if request.method == "POST":
        form = LdapSettingsForm(request.POST, instance=instance)
        if 'test_only' in request.POST:
            if form.is_valid():
                data = form.cleaned_data
                ok, err = _test_ldap_connection(
                    server_uri=data['server_uri'],
                    use_ssl=data['use_ssl'],
                    bind_dn=data.get('bind_dn') or None,
                    bind_password=data.get('bind_password') or None
                )
                if ok:
                    messages.success(request, "LDAP connection test: ✅ Success.")
                else:
                    messages.error(request, f"LDAP connection test failed: {err}")
            else:
                messages.error(request, "Please fix the errors in the form before testing.")
        else:
            # Save settings
            if form.is_valid():
                saved = form.save()
                messages.success(request, "LDAP settings saved.")
                return redirect('home')  # go to your dashboard or wherever
            else:
                messages.error(request, "Please fix the errors in the form.")
    else:
        form = LdapSettingsForm(instance=instance)

    return render(request, "ldap_setup.html", {"form": form})


def _test_ldap_connection(server_uri: str, use_ssl: bool, bind_dn: str | None, bind_password: str | None):
    try:
        tls = None
        if use_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
        server = Server(server_uri, use_ssl=use_ssl, tls=tls, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        # If no search base is configured, ensure we can read RootDSE for default naming context
        try:
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["defaultNamingContext"],
                size_limit=1,
            )
        except Exception:
            pass
        conn.unbind()
        return True, None
    except Exception as e:
        return False, str(e)
    
    
# Reports
def reports_page(request):
	return render(request, 'reports/reports_page.html')

def user_reports_page(request):
    try:
        from .ad_service import list_users
        users = list_users()
    except Exception:
        users = []
    return render(request, 'reports/user/user_reports_page.html', {"users": users})

def ou_reports_page(request):
    try:
        from .ad_service import list_ous
        ous = list_ous()
    except Exception:
        ous = []
    return render(request, 'reports/ou/ou_reports_page.html', {"ous": ous})

def group_reports_page(request):
    try:
        from .ad_service import list_groups
        groups = list_groups()
    except Exception:
        groups = []
    return render(request, 'reports/group/group_reports_page.html', {"groups": groups})

def computer_reports_page(request):
    try:
        from .ad_service import list_computers
        computers = list_computers()
    except Exception:
        computers = []
    return render(request, 'reports/computer/computer_reports_page.html', {"computers": computers})

# Management - User
def user_management(request):
	return render(request, 'management/user/user_management.html')

def unlock_single_user(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        try:
            unlock_user(username)
            messages.success(request, f"User unlocked: {username}")
        except ADServiceError as e:
            messages.error(request, f"Unlock failed: {e}")
    return render(request, 'management/user/unlock/single_user.html')

def unlock_bulk_users(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                username = str(row.get("username", "")).strip()
                if username:
                    unlock_user(username)
            messages.success(request, "Bulk unlock completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk unlock failed: {e}")
    return render(request, 'management/user/unlock/bulk_users.html')

def reset_single_user(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        new_password = request.POST.get("new_password", "")
        confirm_password = request.POST.get("confirm_password", "")
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            try:
                reset_user_password(username, new_password)
                messages.success(request, f"Password reset for {username}.")
            except ADServiceError as e:
                messages.error(request, f"Password reset failed: {e}")
    return render(request, 'management/user/reset/single_user.html')

def reset_bulk_users(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                username = str(row.get("username", "")).strip()
                new_password = str(row.get("new_password", "")).strip()
                if username and new_password:
                    reset_user_password(username, new_password)
            messages.success(request, "Bulk password reset completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk reset failed: {e}")
    return render(request, 'management/user/reset/bulk_users.html')

def lock_single_user(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        try:
            lock_user(username)
            messages.success(request, f"User locked: {username}")
        except ADServiceError as e:
            messages.error(request, f"Lock failed: {e}")
    return render(request, 'management/user/lock/single_user.html')

def lock_bulk_users(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                username = str(row.get("username", "")).strip()
                if username:
                    lock_user(username)
            messages.success(request, "Bulk lock completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk lock failed: {e}")
    return render(request, 'management/user/lock/bulk_users.html')

def update_single_user(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        updates = {
            "givenName": request.POST.get("first_name", "").strip(),
            "sn": request.POST.get("last_name", "").strip(),
            "displayName": request.POST.get("display_name", "").strip(),
            "mail": request.POST.get("email", "").strip(),
            "telephoneNumber": request.POST.get("phone", "").strip(),
            "department": request.POST.get("department", "").strip(),
            "description": request.POST.get("description", "").strip(),
        }
        try:
            update_user(username, updates)
            messages.success(request, f"User updated: {username}")
        except ADServiceError as e:
            messages.error(request, f"Update failed: {e}")
    return render(request, 'management/user/update/single_user.html')

def update_bulk_users(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                username = str(row.get("username", "")).strip()
                if not username:
                    continue
                updates = {
                    "givenName": row.get("first_name"),
                    "sn": row.get("last_name"),
                    "displayName": row.get("display_name"),
                    "mail": row.get("email"),
                    "telephoneNumber": row.get("phone"),
                    "department": row.get("department"),
                    "description": row.get("description"),
                }
                update_user(username, updates)
            messages.success(request, "Bulk update completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk update failed: {e}")
    return render(request, 'management/user/update/bulk_users.html')

def create_single_user(request):
    # Fetch OUs + Groups for dropdowns (GET and also POST re-render on errors)
    try:
        ous = list_ous()     # expects: [{"ou": "...", "dn": "..."}]
    except Exception:
        ous = []

    try:
        groups = list_groups()  # update list_groups to include {"name":..., "dn":...}
    except Exception:
        groups = []

    if request.method == "POST":
        first_name   = request.POST.get("first_name", "").strip()
        last_name    = request.POST.get("last_name", "").strip()
        username     = request.POST.get("username", "").strip()
        email        = request.POST.get("email", "").strip()
        phone        = request.POST.get("phone", "").strip()
        department   = request.POST.get("department", "").strip()
        description  = request.POST.get("description", "").strip()
        password     = request.POST.get("password", "")
        confirm_pass = request.POST.get("confirm_password", "")
        must_change_password = bool(request.POST.get("must_change_password"))
        user_cannot_change_password = bool(request.POST.get("user_cannot_change_password"))
        password_never_expires = bool(request.POST.get("password_never_expires"))
        account_disabled = bool(request.POST.get("account_disabled"))

        # NEW: selected OU + Groups (must match template input names)
        target_ou_dn = request.POST.get("target_ou_dn", "").strip()
        group_dns    = request.POST.getlist("group_dns")  # multi-select values = group DN(s)

        # Basic validation
        if not username or not password:
            messages.error(request, "Username and password are required.")
            return render(
                request,
                "management/user/create/single_user.html",
                {"ous": ous, "groups": groups}
            )

        if password != confirm_pass:
            messages.error(request, "Passwords do not match.")
            return render(
                request,
                "management/user/create/single_user.html",
                {"ous": ous, "groups": groups}
            )

        if not target_ou_dn:
            messages.error(request, "Please select the target OU.")
            return render(
                request,
                "management/user/create/single_user.html",
                {"ous": ous, "groups": groups}
            )

        # Create AD user in chosen OU and add to selected groups
        try:
            create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            phone=phone,
            department=department,
            description=description,
            target_ou_dn=target_ou_dn or None,
            group_dns=group_dns or None,
            must_change_password=must_change_password,
            user_cannot_change_password=user_cannot_change_password,
            password_never_expires=password_never_expires,
            account_disabled=account_disabled,
            )
            messages.success(request, f"User created in AD: {username}")
        except ADServiceError as e:
            messages.error(request, f"Create failed: {e}")
        except Exception as e:
            messages.error(request, f"Unexpected error: {e}")

    return render(
        request,
        "management/user/create/single_user.html",
        {"ous": ous, "groups": groups}
    )

def create_bulk_users(request):
    if request.method == "POST":
        file = request.FILES.get("file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                username = str(row.get("username", "")).strip()
                first_name = str(row.get("first_name", "")).strip()
                last_name = str(row.get("last_name", "")).strip()
                email = str(row.get("email", "")).strip()
                password = str(row.get("password", "")).strip()
                if username and password:
                    create_user(username, first_name, last_name, email, password,
                                str(row.get("phone", "") or "").strip(),
                                str(row.get("department", "") or "").strip(),
                                str(row.get("description", "") or "").strip())
            messages.success(request, "Bulk user creation completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk create failed: {e}")
    return render(request, 'management/user/create/bulk_users.html')

def move_single_user(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        target_ou = request.POST.get("target_ou", "").strip()
        try:
            move_user(username, target_ou)
            messages.success(request, f"User moved: {username}")
        except ADServiceError as e:
            messages.error(request, f"Move failed: {e}")
    return render(request, 'management/user/move/single_user.html')

def move_bulk_users(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                username = str(row.get("username", "")).strip()
                target_ou = str(row.get("target_ou", "")).strip()
                if username and target_ou:
                    move_user(username, target_ou)
            messages.success(request, "Bulk move completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk move failed: {e}")
    return render(request, 'management/user/move/bulk_users.html')


def create_single_computer(request):
    if request.method == "POST":
        computer_name = request.POST.get("computer_name", "").strip()
        ou = request.POST.get("ou", "").strip()
        try:
            if not computer_name:
                messages.error(request, "Computer name is required.")
            else:
                create_computer(computer_name, ou or None)
                messages.success(request, f"Computer created: {computer_name}")
        except ADServiceError as e:
            messages.error(request, f"Create failed: {e}")
    return render(request, 'management/computer/create/single_computer.html')

def create_bulk_computers(request):
    if request.method == "POST":
        file = request.FILES.get("file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("computer_name", "")).strip() or str(row.get("name", "")).strip()
                ou = str(row.get("ou", "")).strip()
                if name:
                    create_computer(name, ou or None)
            messages.success(request, "Bulk computer creation completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk create failed: {e}")
    return render(request, 'management/computer/create/bulk_computers.html')

def computer_management(request):
    return render(request, 'management/computer/computer_management_page.html')

def lock_single_computer(request):
    if request.method == "POST":
        computer_name = request.POST.get("computer_name", "").strip()
        try:
            lock_computer(computer_name)
            messages.success(request, f"Computer locked: {computer_name}")
        except ADServiceError as e:
            messages.error(request, f"Lock failed: {e}")
    return render(request, "management/computer/lock/single_computer.html")

def lock_bulk_computers(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("computer_name", "")).strip() or str(row.get("name", "")).strip()
                if name:
                    lock_computer(name)
            messages.success(request, "Bulk lock completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk lock failed: {e}")
    return render(request, "management/computer/lock/bulk_computers.html")

def unlock_single_computer(request):
    if request.method == "POST":
        computer_name = request.POST.get("computer_name", "").strip()
        try:
            unlock_computer(computer_name)
            messages.success(request, f"Computer unlocked: {computer_name}")
        except ADServiceError as e:
            messages.error(request, f"Unlock failed: {e}")
    return render(request, "management/computer/unlock/single_computer.html")

def unlock_bulk_computers(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("computer_name", "")).strip() or str(row.get("name", "")).strip()
                if name:
                    unlock_computer(name)
            messages.success(request, "Bulk unlock completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk unlock failed: {e}")
    return render(request, "management/computer/unlock/bulk_computers.html")

def move_single_computer(request):
    if request.method == "POST":
        computer_name = request.POST.get("computer_name", "").strip()
        target_ou = request.POST.get("target_ou", "").strip()
        try:
            move_computer(computer_name, target_ou)
            messages.success(request, f"Computer moved: {computer_name}")
        except ADServiceError as e:
            messages.error(request, f"Move failed: {e}")
    return render(request, "management/computer/move/single_computer.html")

def move_bulk_computers(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("computer_name", "")).strip() or str(row.get("name", "")).strip()
                target_ou = str(row.get("target_ou", "")).strip()
                if name and target_ou:
                    move_computer(name, target_ou)
            messages.success(request, "Bulk move completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk move failed: {e}")
    return render(request, "management/computer/move/bulk_computers.html")

def update_single_computer(request):
    if request.method == "POST":
        computer_name = request.POST.get("computer_name", "").strip()
        updates = {
            "description": request.POST.get("description", "").strip(),
        }
        try:
            update_computer(computer_name, updates)
            messages.success(request, f"Computer updated: {computer_name}")
        except ADServiceError as e:
            messages.error(request, f"Update failed: {e}")
    return render(request, "management/computer/update/single_computer.html")

def update_bulk_computers(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("computer_name", "")).strip() or str(row.get("name", "")).strip()
                if not name:
                    continue
                updates = {"description": row.get("description")}
                update_computer(name, updates)
            messages.success(request, "Bulk update completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk update failed: {e}")
    return render(request, "management/computer/update/bulk_computers.html")

def ou_management(request):
    return render(request, 'management/ou/ou_management.html')

def create_single_ou(request):
    if request.method == "POST":
        ou_name = request.POST.get("ou_name", "").strip()
        parent_ou = request.POST.get("parent_ou", "").strip()
        description = request.POST.get("description", "").strip()
        protect = bool(request.POST.get("protect"))

        if not ou_name:
            messages.error(request, "OU Name is required.")
            return render(request, "management/ou/create_single_ou.html")
        try:
            create_ou(ou_name, parent_ou, description, protect)
            messages.success(request, f"OU created: {ou_name}")
            return redirect("ou_management")
        except ADServiceError as e:
            messages.error(request, f"OU create failed: {e}")

    return render(request, "management/ou/create_single_ou.html")

def update_single_ou(request):
    if request.method == "POST":
        ou_dn = request.POST.get("ou_dn", "").strip()
        new_name = request.POST.get("new_name", "").strip()
        description = request.POST.get("description", "").strip()
        protect = bool(request.POST.get("protect"))

        if not ou_dn:
            messages.error(request, "Please select or enter an OU DN.")
            return render(request, "management/ou/update_single_ou.html")

        try:
            update_ou(ou_dn, new_name, description, protect)
            messages.success(request, "OU updated.")
            return redirect("ou_management")
        except ADServiceError as e:
            messages.error(request, f"OU update failed: {e}")

    return render(request, "management/ou/update_single_ou.html")

def move_ou(request):
    if request.method == "POST":
        ou_dn = request.POST.get("ou_dn", "").strip()
        target_parent = request.POST.get("target_parent_dn", "").strip()
        if not ou_dn or not target_parent:
            messages.error(request, "OU DN and target parent DN are required.")
        else:
            try:
                ad_move_ou(ou_dn, target_parent)
                messages.success(request, "OU moved successfully.")
                return redirect("ou_management")
            except ADServiceError as e:
                messages.error(request, f"Move failed: {e}")
    return render(request, "management/ou/move_ou.html")

def delete_ou(request):
    """
    UI shell for deleting an OU.
    Later you'll wire this to AD logic; for now we simulate success/dry-run.
    """
    if request.method == 'POST':
        ou_dn = request.POST.get('ou_dn', '').strip()
        include_children = bool(request.POST.get('include_children'))
        dry_run = bool(request.POST.get('dry_run'))
        confirm = bool(request.POST.get('confirm_delete'))

        if not ou_dn:
            messages.error(request, "Please provide the OU Distinguished Name (DN).")
            return render(request, 'management/ou/delete_ou.html')

        if not confirm:
            messages.error(request, "You must confirm that you understand this action is irreversible.")
            return render(request, 'management/ou/delete_ou.html')

        if dry_run:
            messages.info(request, f"Dry run only. Would delete OU: {ou_dn} (include children: {include_children}).")
            return render(request, 'management/ou/delete_ou.html')
        try:
            delete_ou(ou_dn)
            messages.success(request, f"OU deleted successfully: {ou_dn}")
            return redirect('ou_management')
        except ADServiceError as e:
            messages.error(request, f"Delete failed: {e}")

    return render(request, 'management/ou/delete_ou.html')


def create_bulk_ous(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                ou_name = str(row.get("ou_name", "")).strip()
                parent_ou = str(row.get("parent_ou", "")).strip()
                description = str(row.get("description", "") or "").strip()
                protect = str(row.get("protect", "") or "").strip().lower() in ("1", "true", "yes", "y")
                if ou_name:
                    create_ou(ou_name, parent_ou, description, protect)
            messages.success(request, "Bulk OU create completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk create failed: {e}")
    return render(request, "management/ou/create_bulk_ou.html")


def update_bulk_ous(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                ou_dn = str(row.get("ou_dn", "")).strip()
                new_name = str(row.get("new_name", "") or "").strip()
                description = str(row.get("description", "") or "").strip()
                protect = str(row.get("protect", "") or "").strip().lower() in ("1", "true", "yes", "y")
                if ou_dn:
                    update_ou(ou_dn, new_name, description, protect)
            messages.success(request, "Bulk OU update completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk update failed: {e}")
    return render(request, "management/ou/update_bulk_ou.html")


def delete_bulk_ous(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                ou_dn = str(row.get("ou_dn", "")).strip()
                if ou_dn:
                    delete_ou(ou_dn)
            messages.success(request, "Bulk OU delete completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk delete failed: {e}")
    return render(request, "management/ou/delete_bulk_ou.html")


def move_bulk_ous(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                ou_dn = str(row.get("ou_dn", "")).strip()
                target_parent = str(row.get("target_parent_dn", "")).strip()
                if ou_dn and target_parent:
                    ad_move_ou(ou_dn, target_parent)
            messages.success(request, "Bulk OU move completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk move failed: {e}")
    return render(request, "management/ou/move_bulk_ou.html")

def group_management(request):
    return render(request, 'management/group/group_management_page.html')

def create_single_group(request):
    if request.method == "POST":
        group_name = request.POST.get("group_name", "").strip()
        description = request.POST.get("description", "").strip()
        users = request.POST.get("users", "")
        computers = request.POST.get("computers", "")
        user_list = [u.strip() for u in users.split(",") if u.strip()]
        computer_list = [c.strip() for c in computers.split(",") if c.strip()]
        members = [m for m in (user_list + computer_list) if m]
        if not group_name:
            messages.error(request, "Group name is required.")
        else:
            try:
                create_group(group_name, description, members)
                messages.success(request, f"Group created: {group_name}")
            except ADServiceError as e:
                messages.error(request, f"Group creation failed: {e}")
    return render(request, 'management/group/create/single_group.html')


def update_single_group(request):
    if request.method == "POST":
        group_name = request.POST.get("group_name", "").strip()
        description = request.POST.get("description", "").strip()
        add_members_raw = request.POST.get("add_members", "")
        remove_members_raw = request.POST.get("remove_members", "")
        add_members = [m.strip() for m in add_members_raw.split(",") if m.strip()]
        remove_members = [m.strip() for m in remove_members_raw.split(",") if m.strip()]
        try:
            update_group(group_name, description, add_members, remove_members)
            messages.success(request, f"Group updated: {group_name}")
        except ADServiceError as e:
            messages.error(request, f"Update failed: {e}")
    return render(request, "management/group/update/single_group.html")


def delete_single_group(request):
    if request.method == "POST":
        group_name = request.POST.get("group_name", "").strip()
        confirm = request.POST.get("confirm_delete")
        if not confirm:
            messages.error(request, "Please confirm deletion.")
        else:
            try:
                delete_group(group_name)
                messages.success(request, f"Group deleted: {group_name}")
            except ADServiceError as e:
                messages.error(request, f"Delete failed: {e}")
    return render(request, "management/group/delete/single_group.html")


def move_single_group(request):
    if request.method == "POST":
        group_name = request.POST.get("group_name", "").strip()
        target_ou = request.POST.get("target_ou", "").strip()
        try:
            move_group(group_name, target_ou)
            messages.success(request, f"Group moved: {group_name}")
        except ADServiceError as e:
            messages.error(request, f"Move failed: {e}")
    return render(request, "management/group/move/single_group.html")


def create_bulk_groups(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("group_name", "")).strip()
                description = str(row.get("description", "") or "").strip()
                if name:
                    create_group(name, description, [])
            messages.success(request, "Bulk group create completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk create failed: {e}")
    return render(request, "management/group/create/bulk_groups.html")


def update_bulk_groups(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("group_name", "")).strip()
                if not name:
                    continue
                description = str(row.get("description", "") or "").strip()
                add_members = [m.strip() for m in str(row.get("add_members", "") or "").split(",") if m.strip()]
                remove_members = [m.strip() for m in str(row.get("remove_members", "") or "").split(",") if m.strip()]
                update_group(name, description, add_members, remove_members)
            messages.success(request, "Bulk group update completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk update failed: {e}")
    return render(request, "management/group/update/bulk_groups.html")


def delete_bulk_groups(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("group_name", "")).strip()
                if name:
                    delete_group(name)
            messages.success(request, "Bulk group delete completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk delete failed: {e}")
    return render(request, "management/group/delete/bulk_groups.html")


def move_bulk_groups(request):
    if request.method == "POST":
        file = request.FILES.get("excel_file")
        try:
            rows = _read_excel_rows(file)
            for row in rows:
                name = str(row.get("group_name", "")).strip()
                target_ou = str(row.get("target_ou", "")).strip()
                if name and target_ou:
                    move_group(name, target_ou)
            messages.success(request, "Bulk group move completed.")
        except ADServiceError as e:
            messages.error(request, f"Bulk move failed: {e}")
    return render(request, "management/group/move/bulk_groups.html")

def user_reports(request):
    try:
        from .ad_service import list_users
        users = list_users()
    except Exception:
        users = []
    return render(request, 'reports/user/user_reports_page.html', {"users": users})

def computer_reports(request):
    try:
        from .ad_service import list_computers
        computers = list_computers()
    except Exception:
        computers = []
    return render(request, 'reports/computer/computer_reports_page.html', {"computers": computers})

def group_reports(request):
    try:
        from .ad_service import list_groups
        groups = list_groups()
    except Exception:
        groups = []
    return render(request, 'reports/group/group_reports_page.html', {"groups": groups})

def ou_reports(request):
    try:
        from .ad_service import list_ous
        ous = list_ous()
    except Exception:
        ous = []
    return render(request, 'reports/ou/ou_reports_page.html', {"ous": ous})

RESOURCES = ["users", "computers", "ous", "groups", "reports"]
ACTIONS = ["create", "delete", "modify", "lock", "unlock", "reset", "view_reports"]


@require_http_methods(["GET"])
def admin_hub(request):
    """Render the admin page with resources/actions lists."""
    context = {
        "resources": RESOURCES,
        "actions": ACTIONS,
    }
    return render(request, "admin/admin_hub.html", context)


@require_POST
def admin_create_helpdesk_user(request):
    """Create a user + store selected permissions matrix as JSON."""
    username      = request.POST.get("username")
    email         = request.POST.get("email")
    temp_password = request.POST.get("temp_password")
    first_name    = request.POST.get("first_name") or ""
    last_name     = request.POST.get("last_name") or ""
    role          = request.POST.get("role") or "custom"
    ou            = request.POST.get("ou") or ""
    scope         = request.POST.get("scope") or ""

    if not username or not temp_password:
        messages.error(request, "Username and temporary password are required.")
        return redirect("admin_hub")

    # Collect permissions from multi-selects
    perms = {}
    for r in RESOURCES:
        perms[r] = request.POST.getlist(f"perms_{r}[]")  # e.g., ['create','modify']

    # Create user
    User = get_user_model()
    # use create_user for your custom manager; adjust fields as needed
    user = User.objects.create_user(username=username, password=temp_password)
    user.email = email
    user.first_name = first_name
    user.last_name = last_name
    user.save()

    # Save profile (role, OU, scope, and permissions)
    HelpdeskProfile.objects.create(
        user=user,
        role=role,
        ou=ou,
        scope=scope,
        permissions=perms
    )

    messages.success(request, f"User {username} created with selected permissions.")
    return redirect("admin_hub")


# Stubs for other tabs (optional — implement your logic later)
@require_POST
def admin_assign_roles(request):
    messages.info(request, "Role assignment not implemented yet.")
    return redirect("admin_hub")

@require_POST
def admin_auth_settings(request):
    messages.success(request, "Authentication settings saved (stub).")
    return redirect("admin_hub")

@require_http_methods(["GET"])
def admin_logs(request):
    # You can read filters here and pass to template; stub for now
    messages.info(request, "Logs filtering not implemented yet.")
    return redirect("admin_hub")

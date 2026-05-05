from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from .views import *

urlpatterns = [

    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('select-domain/', select_domain, name='select_domain'),
    path('', index, name='home'),
    path('ldap/setup/', ldap_setup, name='ldap_setup'),

    # Management URLs

    # Computer management URLs
    path('computer/create/single/', create_single_computer, name='create_single_computer'),
    path('computer/create/bulk/', create_bulk_computers, name='create_bulk_computers'),
    path('computer/lock/single/', lock_single_computer, name='lock_single_computer'),
    path('computer/lock/bulk/', lock_bulk_computers, name='lock_bulk_computers'),
    path('computer/unlock/single/', unlock_single_computer, name='unlock_single_computer'),
    path('computer/unlock/bulk/', unlock_bulk_computers, name='unlock_bulk_computers'),
    path('computer/move/single/', move_single_computer, name='move_single_computer'),
    path('computer/move/bulk/', move_bulk_computers, name='move_bulk_computers'),
    path('computer/update/single/', update_single_computer, name='update_single_computer'),
    path('computer/update/bulk/', update_bulk_computers, name='update_bulk_computers'),
    path('computer_management/', computer_management, name='computer_management'),

    # User management URLs
    path('user_management/', user_management, name='user_management'),
    path('user/create/single/', create_single_user, name='create_single_user'),
    path('user/create/bulk_users/', create_bulk_users, name='bulk_users'),
    path('user/update/single/', update_single_user, name='update_single_user'),
    path('user/update/bulk/', update_bulk_users, name='update_bulk_users'),
    path('user/lock/single/', lock_single_user, name='lock_single_user'),
    path('user/lock/bulk/', lock_bulk_users, name='lock_bulk_users'),
    path('user/unlock/single_user/', unlock_single_user, name='unlock_single_user'),
    path('user/unlock/bulk_users/', unlock_bulk_users, name='unlock_bulk_users'),
    path('user/reset/single_user/', reset_single_user, name='reset_password_single_user'),
    path('user/reset/bulk_users/', reset_bulk_users, name='reset_password_bulk_users'),
    path('user/move/single_user/', move_single_user, name='move_single_user'),
    path('user/move/bulk_users/', move_bulk_users, name='move_bulk_users'),

    # OU management URLs
    path('ou_management/', ou_management, name='ou_management'),
    path("ou/create/single/", create_single_ou, name="create_single_ou"),
    path("ou/create/bulk/", create_bulk_ous, name="create_bulk_ous"),
    path("ou/update/single/", update_single_ou, name="update_single_ou"),
    path("ou/update/bulk/", update_bulk_ous, name="update_bulk_ous"),
    path("ou/move/", move_ou, name="move_ou"),
    path("ou/move/bulk/", move_bulk_ous, name="move_bulk_ous"),
    path('ou/delete/', delete_ou, name='delete_ou'),
    path('ou/delete/bulk/', delete_bulk_ous, name='delete_bulk_ous'),

    # Group management URLs
    path('group_management/', group_management, name='group_management'),
    path('group/create/single/', create_single_group, name='create_single_group'),
    path("groups/search-users/", search_users_view, name="search_users"),
    path("groups/search-computers/", search_computers_view, name="search_computers"),
    path("groups/search-groups/", search_groups_view, name="search_groups"),
    path('group/create/bulk/', create_bulk_groups, name='create_bulk_groups'),
    path('group/update/single/', update_single_group, name='update_single_group'),
    path("ajax/ad/search-objects/", search_directory_objects_ajax, name="search_directory_objects_ajax"),
    path("ajax/ad/group-members/", get_group_members_ajax, name="get_group_members_ajax"),
    path('group/update/bulk/', update_bulk_groups, name='update_bulk_groups'),
    path('group/delete/single/', delete_single_group, name='delete_single_group'),
    path('group/delete/bulk/', delete_bulk_groups, name='delete_bulk_groups'),
    path('group/move/single/', move_single_group, name='move_single_group'),
    path('group/move/bulk/', move_bulk_groups, name='move_bulk_groups'),

    # Report URLs
    
    path("reports/", reports_page, name="reports_page"),
    path("reports/user/", user_reports_page, name="user_reports_page"),
    path("reports/computer/", computer_reports_page, name="computer_reports_page"),
    path("reports/ou/", ou_reports_page, name="ou_reports_page"),
    path("reports/group/", group_reports_page, name="group_reports_page"),


    # Admin hub & actions
    path('admin_hub/', admin_hub, name='admin_hub'),
    path('admin_hub/create-helpdesk-user/', admin_create_helpdesk_user, name='admin_create_helpdesk_user'),
    path('admin_hub/assign-roles/', admin_assign_roles, name='admin_assign_roles'),
    path('admin_hub/auth-settings/', admin_auth_settings, name='admin_auth_settings'),
    path('admin_hub/logs/', admin_logs, name='admin_logs'), 
] + static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])

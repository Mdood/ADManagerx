from django.core.management.base import BaseCommand
from ldap3 import Server, Connection, ALL
from ADManagerX.models import User, Group, Computer, OU

class Command(BaseCommand):
    help = 'Sync Active Directory data to MySQL'

    def handle(self, *args, **options):
        server = Server('your-ad-server.example.com', get_info=ALL)
        conn = Connection(server, 'CN=ldap_user,OU=Users,DC=example,DC=com', 'your_ldap_password', auto_bind=True)
        # Example: Fetch users
        conn.search('OU=Users,DC=example,DC=com', '(objectClass=user)', attributes=['sAMAccountName', 'displayName', 'department'])
        for entry in conn.entries:
            User.objects.update_or_create(
                username=entry.sAMAccountName.value,
                defaults={'first_name': entry.displayName.value, 'department': entry.department.value}
            )
        # Repeat for groups, computers, OUs as needed
        self.stdout.write(self.style.SUCCESS('AD sync complete'))
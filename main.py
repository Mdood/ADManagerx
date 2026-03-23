from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD, MODIFY_REPLACE
from tkinter import *
from tkinter import ttk
import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
import pandas as pd
import numpy as np
import random
import mysql.connector
import time 
import winrm
from imap_tools import MailBox, AND
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# Connect to the MySQL server
mydb = mysql.connector.connect(
    host="MySQL_Server",
    user="Work",
    password="Waleed55667604$",
    database="Domain_DataBase"
)
mycursor = mydb.cursor()

# SQL Queries
sql_add_users = "INSERT INTO users(it, full_name, hr_id, telephone, title, project, nt, password, date, time) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
sql_add_tempo_users = "INSERT INTO tempo_users(full_name, hr_id, telephone, title, project, nt, password) VALUES (%s,%s,%s,%s,%s,%s,%s)"
sql_delete_users = "DELETE FROM users"
sql_delete_tempo_users = "DELETE FROM tempo_users"
sql_query_users = "SELECT * FROM users"
sql_query_tempo_users = "SELECT * FROM tempo_users"
sql_duplicates = "INSERT INTO duplicates(full_name, hr_id, telephone, title, project, nt, password) VALUES (%s,%s,%s,%s,%s,%s,%s)"
sql_delete_duplicates = "DELETE FROM duplicates"
sql_query_duplicates = "SELECT * FROM duplicates"

# Initialize the main application window
root = ttk.Window(themename="flatly")
root.geometry('500x500')
root.resizable(True, True)

# Global Variables
it = None
session = None
domain = None
domain_parts = None
dc1 = None
dc2 = None
domain_user = None
domain_password = None
domain_host = None
server = None
conn = None
ex = None
Projects = {}
default_password = "P@ssw0rd"
default_password = default_password.encode('utf-16-le')
stop_running = False
imap_server = 'imap.gmail.com'
sender_email = None
receiver_email = None
subject = 'Creation Mail'
body = 'Created this batch, Check the Excel Sheet for Details.'
mail_password = None


def Mail_Sending():
    
    creation_path = 'Creation.xlsx'
    duplicate_path = 'Duplicates.xlsx'
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Attach the Excel file
    with open(creation_path, 'rb') as file:
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(file.read())
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', f'attachment; filename="{creation_path}"')
        msg.attach(attachment)
        
    with open(duplicate_path, 'rb') as file:
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(file.read())
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', f'attachment; filename="{duplicate_path}"')
        msg.attach(attachment)

    # Send email via SMTP
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, mail_password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

    print('Email sent successfully!')


def Mail_Checking():
    global ex, stop_running
    
    if not stop_running:
        with MailBox(imap_server).login(sender_email, mail_password, 'INBOX') as mb:
            # Search for emails with attachments
            # You can modify the search criteria based on your needs
            for msg in mb.fetch(AND(seen=False), limit=5, reverse=True, mark_seen=True):
                if msg.subject == "Create NT":
                    for att in msg.attachments:
                        if att.filename.endswith('.xlsx'):  # Check if the attachment is an Excel file
                            print(f"Found attachment: {att.filename}")
                            # Read the attachment as a pandas DataFrame
                            ex = pd.read_excel(io.BytesIO(att.payload), engine='openpyxl')
                            
                    names = ex['Full Name'].dropna().tolist()
                    hr_ids = ex['HR ID'].dropna().tolist()
                    phones = ex['Phone no.'].dropna().tolist()
                    titles = ex['Title'].dropna().tolist()
                    projects = ex['Project'].dropna().tolist()

                    # Fetch existing projects from LDAP
                    parent_ou_dn = f'DC={dc1},DC={dc2}'
                    search_filter = '(objectClass=organizationalUnit)'
                    conn.search(parent_ou_dn, search_filter, search_scope=SUBTREE, attributes=['distinguishedName', 'ou'])


                    if conn.entries:
                        for entry in conn.entries:
                            Projects[str(entry.ou)] = str(entry.distinguishedName)

                    # Add users to LDAP and MySQL
                    for i in range(len(names)):
                        if projects[i] not in Projects:
                            pass
                        
                        found = False
                        full_name = names[i]
                        fname, lname = full_name.split(" ", 1)
                        user_dn = f'CN={names[i]},{Projects[projects[i]]}'
                        user_nt = NT_Creation(full_name)

                        parent_ou_dn = f'DC=vmwarelab,DC=local'
                        search_filter = '(objectClass=user)'
                        conn.search(parent_ou_dn, search_filter, search_scope=SUBTREE, attributes=['cn'])

                        for entry in conn.entries:
                            if full_name == entry.cn:
                                found = True
                        if not found:
                            conn.add(
                                user_dn,
                                ['User'],
                                {
                                    'cn': names[i],
                                    'sn': lname,
                                    'givenName': fname,
                                    'displayName': names[i],
                                    'sAMAccountName': user_nt,
                                    'userPrincipalName': f'{user_nt}@{domain}',
                                    'title': titles[i],
                                    'telephoneNumber': str(phones[i]),
                                    'physicalDeliveryOfficeName' : hr_ids[i],
                                    'department' : projects[i],
                                    'company' : 'Etisal-int.com'
                                }
                            )

                            if 'Agent' in titles[i]:
                                group_dn = f"CN=Agent-Group,OU=Groups,DC={dc1},DC={dc2}"
                                conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                            elif "Team Leader" in titles[i]:
                                group_dn = f"CN=Team-Leader-Group,OU=Groups,DC={dc1},DC={dc2}"
                                conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

                            session.run_ps(f'Enable-ADAccount -Identity {user_nt}')

                            session.run_ps(f'Set-ADUser -Identity {user_nt} -ChangePasswordAtLogon $True')
                            # Get the current date
                            current_date = time.strftime('%A, %B %d, %Y')  # Example: Monday, August 30, 2024
                            # Get the current time in 12-hour format with AM/PM
                            current_time = time.strftime('%I:%M:%S %p')
                            mycursor.execute(sql_add_users, (it ,names[i], hr_ids[i], str(phones[i]), titles[i], projects[i], user_nt, default_password.decode('utf-16-le'), current_date, current_time))
                            mycursor.execute(sql_add_tempo_users, (names[i], hr_ids[i], str(phones[i]), titles[i], projects[i], user_nt, default_password.decode('utf-16-le')))
                            mydb.commit()
                        else:
                            mycursor.execute(sql_duplicates, (names[i], hr_ids[i], str(phones[i]), titles[i], projects[i], user_nt, default_password.decode('utf-16-le')))
                            mydb.commit()
                            pass
                    df = pd.read_sql(sql_query_tempo_users, mydb)
                    df.to_excel("Creation.xlsx", index=False, engine='openpyxl')
                    dd = pd.read_sql(sql_query_duplicates, mydb)
                    dd.to_excel("Duplicates.xlsx", index=False, engine="openpyxl")
                    mycursor.execute(sql_delete_tempo_users)
                    mycursor.execute(sql_delete_duplicates)
                    mydb.commit()
                    ex = None
        
                    Mail_Sending()            
        root.after(10000, Mail_Checking)

def Logs():
    df = pd.read_sql(sql_query_users, mydb)
    df.to_excel("logs.xlsx", index=False, engine='openpyxl')
    mycursor.execute(sql_delete_users)
    mydb.commit()
    messagebox.showinfo("Logs", "Created logs.xlsx for the logs")

def is_sam_account_name_unique(sam_account_name):
    global dc1, dc2
    search_base = f'dc={dc1},dc={dc2}'
    search_filter = f'(&(objectClass=user)(sAMAccountName={sam_account_name}))'
    conn.search(search_base, search_filter, attributes=['sAMAccountName'])
    return not conn.entries

def Home_Display():
    """Displays the home login page."""
    hide_all()
    
    input_frame.pack()  # Using pack() here is okay because it's for the frame
    lb_user.grid(row=1, column=0, padx=10, pady=10)  # Use grid for layout
    ent_user.grid(row=1, column=1, padx=10, pady=10)
    lb_password.grid(row=2, column=0, padx=10, pady=10)
    ent_password.grid(row=2, column=1, padx=10, pady=10)
    btn_user.grid(row=3, column=0, columnspan=2, pady=20) 
    btn_auto.grid(row=4, column=0, columnspan=2) 

def First_Login():
    """Displays the initial login for LDAP setup."""
    hide_all()
    btn_ldap.pack(pady=60)

def Add_Ldap():
    """Displays the LDAP configuration page."""
    hide_all()
    
    input_frame.pack()
    lb_sender_mail.grid(row=1, column=0)
    ent_sender_mail.grid(row=1, column=1)
    lb_reciever_mail.grid(row=2, column=0)
    ent_reciever_mail.grid(row=2, column=1)
    lb_app_password.grid(row=3, column=0)
    ent_app_password.grid(row=3, column=1)
    lb_domain_host.grid(row=4, column=0)
    ent_domain_host.grid(row=4, column=1)
    lb_domain.grid(row=5, column=0)
    ent_domain.grid(row=5, column=1)
    lb_us_do.grid(row=6, column=0)
    ent_us_do.grid(row=6, column=1)
    lb_pas_do.grid(row=7, column=0)
    ent_pas_do.grid(row=7, column=1)
    btn_connect.grid(row=8, column=0, columnspan=2, pady=20)

def Admin_Page():
    """Displays the admin page after successful LDAP connection."""
    hide_all()
    
    btn_group.pack()
    btn_create_user.pack(pady=10)
    btn_reset_page.pack()
    btn_unlock_admin_page.pack(pady=10)
    btn_lock.pack()
    btn_logs.pack(pady=10)
    btn_home.pack()

def HelpDesk():
    """Displays the HelpDesk page."""
    hide_all()
    
    btn_create_user.pack()
    btn_reset_helpdesk_page.pack(pady=10)
    btn_unlock_helpdesk_page.pack()
    btn_lock.pack(pady=10)
    btn_home.pack()

def Check():
    """Validates the user credentials and assigns them to a role based on group membership."""
    global it
    admin_dn = f"CN=Admin,OU=Groups,DC={dc1},DC={dc2}"
    helpdesk_dn = f"CN=IT-HELPDESK,OU=Groups,DC={dc1},DC={dc2}"
    user = str(ent_user.get())
    it = user
    user_password = str(ent_password.get())
    conn.search(search_base=f'DC={dc1},DC={dc2}', search_filter=f'(sAMAccountName={user})', attributes=['memberOf'])

    if conn.entries:
        user_entry = conn.entries[0]
        member_of = user_entry.memberOf.values
        c = Connection(server, user=f'{user}@{domain}', password=user_password)

        if c.bind():
            if admin_dn in member_of:
                Admin_Page()
            elif helpdesk_dn in member_of:
                HelpDesk()
                
        else:
            messagebox.showerror("Error", "Wrong Username or Password")
            Home_Display()

def Reset_Page():
    """Displays the password reset page."""
    hide_all()
    
    input_frame.pack()
    lb_user_nt.grid(row=0, column=0)
    ent_user_nt.grid(row=0, column=1)
    btn_reset.grid(row=1, column=0, columnspan=2, pady=20)
    btn_admin_page.pack(pady=10)
    
def Reset_Helpdesk_Page():
     """Displays the password reset page."""
     hide_all()
     
     input_frame.pack()
     lb_user_nt.grid(row=0, column=0)
     ent_user_nt.grid(row=0, column=1)
     btn_reset_helpdesk.grid(row=1, column=0, columnspan=2, pady=20)
     btn_helpdesk_page.pack(pady=10)
     
def Reset_Helpdesk():
    """Resets the user's password."""
    base_dn = f'DC={dc1},DC={dc2}'
    sAMAccountName = ent_user_nt.get()
    global default_password

    conn.search(
        search_base=base_dn,
        search_filter=f'(sAMAccountName={sAMAccountName})',
        search_scope=SUBTREE,
        attributes=['distinguishedName']
    )

    if conn.entries:
        user_entry = conn.entries[0]
        dn = user_entry.distinguishedName.value  # Ensure DN is a string
        if "Users" in dn:
            messagebox.showerror("Error", "Can't Reset Password for this User")
            return
        else:
            session.run_ps(f"Set-ADAccountPassword -Identity {sAMAccountName} -NewPassword (ConvertTo-SecureString -AsPlainText 'P@ssw0rd' -Force) -Reset")
            session.run_ps(f'Set-ADUser -Identity {sAMAccountName} -ChangePasswordAtLogon $True')
            messagebox.showinfo("Success", f"Done")
    else:
        messagebox.showerror("Error", "No entries found.")


def Reset():
    """Resets the user's password."""
    base_dn = f'DC={dc1},DC={dc2}'
    sAMAccountName = ent_user_nt.get()
    global default_password

    conn.search(
        search_base=base_dn,
        search_filter=f'(sAMAccountName={sAMAccountName})',
        search_scope=SUBTREE,
        attributes=['distinguishedName']
    )

    if conn.entries:
        
        session.run_ps(f'Set-ADUser -Identity {sAMAccountName} -ChangePasswordAtLogon $True')
        messagebox.showinfo("Success", f"Done")
    else:
        messagebox.showerror("Error", "No entries found.")

def Ldap():
    """Handles LDAP connection and navigation to admin page."""
    global mycursor, domain, domain_parts, dc1, dc2, domain_user, domain_password, server, conn, domain_host, session, sender_email,receiver_email, mail_password

    domain_host = ent_domain_host.get()
    domain = ent_domain.get().strip()
    domain_parts = domain.split('.')

    if len(domain_parts) != 2:
        messagebox.showwarning("Input Error", "Invalid domain format. Please use 'domain.com'.")
        return

    dc1, dc2 = domain_parts[0], domain_parts[1]
    domain_user = ent_us_do.get().strip()
    domain_password = ent_pas_do.get().strip()
    sender_email = ent_sender_mail.get().strip()
    receiver_email = ent_reciever_mail.get().strip()
    mail_password = ent_app_password.get().strip()

    sql_domain = "INSERT INTO domain (domain_server,domain_user,domain_pass,domain_host) VALUES (%s,%s,%s,%s)"
    sql_mail = "INSERT INTO mail_server (SENDER,RECIEVER,APP_PASSWORD) VALUES (%s,%s,%s)"
    mycursor.execute(sql_domain, (domain, domain_user, domain_password, domain_host))
    mycursor.execute(sql_mail,(sender_email,receiver_email,mail_password))
    mydb.commit()

    server = Server(domain, get_info=ALL)
    conn = Connection(server, user=f'{domain_user}@{domain}', password=domain_password,auto_bind=True)
    session = winrm.Session(domain_host, auth=('{}@{}'.format(domain_user,domain), domain_password), transport='ntlm')
    

    if not conn.bind():
        messagebox.showerror("Connection Error", "Wrong Credentials")
    else:
        messagebox.showinfo("Connected", "Connected")
        Home_Display()

def Load_Excel_Create():
    """Loads user data from an Excel file and triggers user creation."""
    global ex
    filepath = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx *.xls")], title="Select an Excel file")

    if filepath:
        try:
            ex = pd.read_excel(filepath, engine='openpyxl')
            User()
        except Exception as e:
            messagebox.showerror("Error", f"Error reading Excel file: {e}")
            
def Load_Excel_Lock():
    """Loads user data from an Excel file and triggers user creation."""
    global ex
    filepath = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx *.xls")], title="Select an Excel file")

    if filepath:
        try:
            ex = pd.read_excel(filepath, engine='openpyxl')
            admin_dn = f"CN=Admin,OU=Groups,DC={dc1},DC={dc2}"
            helpdesk_dn = f"CN=IT-HELPDESK,OU=Groups,DC={dc1},DC={dc2}"
            user = str(ent_user.get())
            user_password = str(ent_password.get())
            conn.search(search_base=f'DC={dc1},DC={dc2}', search_filter=f'(sAMAccountName={user})', attributes=['memberOf'])

            if conn.entries:
                user_entry = conn.entries[0]
                member_of = user_entry.memberOf.values
                if admin_dn in member_of:
                    Lock_Admin()
                elif helpdesk_dn in member_of:
                    Lock_Helpdesk()
                
            
        except Exception as e:
            messagebox.showerror("Error", f"Error reading Excel file: {e}")

def NT_Creation(full_name):
    """Generates a unique NT username."""
    name_parts = full_name.lower().split()
    
    first_name = name_parts[0]
    last_name = name_parts[1]
    middle_names = [' ',name_parts[2], name_parts[3]]
    middle_names2 = [name_parts[2], name_parts[3]]
    names = [last_name,name_parts[2], name_parts[3]]
    
    random_char = np.random.choice(middle_names)
    random_char2 = np.random.choice(middle_names2)
    random_name = random.choice(names)
    
    base_name = f"{first_name}.{last_name}"
    sam_account_name = base_name
    
    while (len(sam_account_name) <=20) and (not is_sam_account_name_unique(sam_account_name)):
        base_name = f"{first_name}.{random_char2[0]}{random_name}{random_char[0]}"
        sam_account_name = f"{base_name}"
        
    return sam_account_name

def User():
    """Processes the loaded Excel data and creates users in LDAP."""
    global Projects, dc1, dc2, conn, ex, domain, mycursor

    if ex is not None:
        names = ex['Full Name'].dropna().tolist()
        hr_ids = ex['HR ID'].dropna().tolist()
        phones = ex['Phone no.'].dropna().tolist()
        titles = ex['Title'].dropna().tolist()
        projects = ex['Project'].dropna().tolist()

        # Fetch existing projects from LDAP
        parent_ou_dn = f'DC={dc1},DC={dc2}'
        search_filter = '(objectClass=organizationalUnit)'
        conn.search(parent_ou_dn, search_filter, search_scope=SUBTREE, attributes=['distinguishedName', 'ou'])

        if conn.entries:
            for entry in conn.entries:
                Projects[str(entry.ou)] = str(entry.distinguishedName)

        # Add users to LDAP and MySQL
        for i in range(len(names)):
            if projects[i] not in Projects:
                messagebox.showerror("Error", f'Error, wrong project for {names[i]}')
                return

            full_name = names[i]
            fname, lname = full_name.split(" ", 1)
            user_dn = f'CN={names[i]},{Projects[projects[i]]}'
            user_nt = NT_Creation(full_name)
            
            conn.add(
                user_dn,
                ['User'],
                {
                    'cn': names[i],
                    'sn': lname,
                    'givenName': fname,
                    'displayName': names[i],
                    'sAMAccountName': user_nt,
                    'userPrincipalName': f'{user_nt}@{domain}',
                    'title': titles[i],
                    'telephoneNumber': str(phones[i]),
                    'physicalDeliveryOfficeName' : hr_ids[i],
                    'department' : projects[i],
                    'company' : 'Etisal-int.com'
                }
            )
            
            if 'Agent' in titles[i]:
                group_dn = f"CN=Agent-Group,OU=Groups,DC={dc1},DC={dc2}"
                conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
            elif "Team Leader" in titles[i]:
                group_dn = f"CN=Team-Leader-Group,OU=Groups,DC={dc1},DC={dc2}"
                conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                
            session.run_ps(f'Enable-ADAccount -Identity {user_nt}')

            session.run_ps(f'Set-ADUser -Identity {user_nt} -ChangePasswordAtLogon $True')
            # Get the current date
            current_date = time.strftime('%A, %B %d, %Y')  # Example: Monday, August 30, 2024
            # Get the current time in 12-hour format with AM/PM
            current_time = time.strftime('%I:%M:%S %p')
            mycursor.execute(sql_add_users, (it ,names[i], hr_ids[i], str(phones[i]), titles[i], projects[i], user_nt, default_password.decode('utf-16-le'), current_date, current_time))
            mycursor.execute(sql_add_tempo_users, (names[i], hr_ids[i], str(phones[i]), titles[i], projects[i], user_nt, default_password.decode('utf-16-le')))
            mydb.commit()
            
        df = pd.read_sql(sql_query_tempo_users, mydb)
        df.to_excel("Creation.xlsx", index=False, engine='openpyxl')
        mycursor.execute(sql_delete_tempo_users)
        mydb.commit()
        ex = None
        messagebox.showinfo("Success", "Creation Done and Created Creation.xlsx for the Creation")
        
        
def get_user_account_control(dn):
    conn.search(dn, '(objectClass=user)', attributes=['userAccountControl'])
    if conn.entries:
        return int(conn.entries[0].userAccountControl.value)
    return None

def Unlock_Helpdesk_Page():
    hide_all()
    
    input_frame.pack()
    lb_user_nt.grid(row=0, column=0)
    ent_user_nt.grid(row=0, column=1)
    btn_unlock.grid(row=1, column=0, columnspan=2, pady=20)
    btn_helpdesk_page.pack(pady=10)
    
def Unlock_Admin_Page():
    hide_all()
    
    input_frame.pack()
    lb_user_nt.grid(row=0, column=0)
    ent_user_nt.grid(row=0, column=1)
    btn_unlock.grid(row=1, column=0, columnspan=2, pady=20)
    btn_admin_page.pack(pady=10)

def unlock_user():
    base_dn = f'DC={dc1},DC={dc2}'
    sAMAccountName = ent_user_nt.get()

    conn.search(
        search_base=base_dn,
        search_filter=f'(sAMAccountName={sAMAccountName})',
        search_scope=SUBTREE,
        attributes=['distinguishedName']
    )
    
    if conn.entries:
        user_entry = conn.entries[0]
        dn = user_entry.distinguishedName.values
        session.run_ps(f'Enable-ADAccount -Identity {sAMAccountName}')
        messagebox.showinfo("Successful", f"Unlocked {sAMAccountName}")
        
def Group_Page():
    hide_all()
    
    input_frame.pack()
    lb_group_name.grid(row=0, column=0)
    ent_group_name.grid(row=0, column=1)
    lb_group_type.grid(row=1, column=0)
    group_type.grid(row=1, column=1)
    btn_create_group.grid(row=2, column=0, columnspan=2, pady=20)
    btn_admin_page.pack(pady=10)

def Group_Creation():
    Type_no = None
    dl_shortname = ent_group_name.get().strip()  # Get the group name from the ttk.entry widget
    Type = group_type.get()
    
    if Type == 'Security':
        Type_no = -2147483640
    else:
        Type_no = 8
    
    if not dl_shortname:
        messagebox.showerror("Input Error", "Group name cannot be empty.")
        return

    dl_group_dn = f'CN={dl_shortname},OU=Groups,DC={dc1},DC={dc2}'
    object_class = ['top', 'group']
    attr = {
        'cn': dl_shortname,
        'groupType': Type_no,  
        'sAMAccountName': dl_shortname
    }
    if conn.add(dl_group_dn, object_class, attr):
        if conn.result['result'] == 0:
            messagebox.showinfo("Success", f"Group '{dl_shortname}' added successfully!")
            Admin_Page()
        else:
            messagebox.showerror("Modification Error", f"Failed to modify group: {conn.result['description']}")
    else:
        messagebox.showerror("Creation Error", f"Failed to create group: {conn.result['description']}")
        
def Lock_Helpdesk():
    
    global ex

    if ex is not None:
        NTs = ex['NT'].dropna().tolist()

        for nt in NTs:
            base_dn = f'DC={dc1},DC={dc2}'

            conn.search(
                search_base=base_dn,
                search_filter=f'(sAMAccountName={nt})',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )

            if conn.entries:
                user_entry = conn.entries[0]
                dn = user_entry.distinguishedName.values
                if "Users" in dn:
                    messagebox.showerror("Error", f"Can't Disable this User {nt}")
                    return
                session.run_ps(f"Disable-ADAccount -Identity {nt}")
        messagebox.showinfo("Successful", "Disabled Users")
    
def Lock_Admin():
    
    global ex

    if ex is not None:
        NTs = ex['NT'].dropna().tolist()

        for nt in NTs:
            base_dn = f'DC={dc1},DC={dc2}'
            sAMAccountName = nt

            conn.search(
                search_base=base_dn,
                search_filter=f'(sAMAccountName={sAMAccountName})',
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )

            if conn.entries:
                user_entry = conn.entries[0]
                dn = user_entry.distinguishedName.values
                current_uac = get_user_account_control(dn)
                if current_uac is not None:
                    new_uac = current_uac | 2   
                    conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
                    print(f"{sAMAccountName} Disabled.")
                    
                else:
                    print(f"Failed to retrieve userAccountControl for {sAMAccountName}")
                    messagebox.showerror("Error", f"Failed to retrieve userAccountControl for {sAMAccountName}")
                    return
        messagebox.showinfo("Successful", "Disabled Users")
    
def stop_function():
    global stop_running
    stop_running = True
    print("Stopped by button press")
    Home_Display()

def Auto_Page():
    hide_all()
    global label, stop_running, it
    stop_running = False
    it = 'AutoPy'
    
    input_frame.pack()
    btn_stop_auto.pack()
    Mail_Checking()

def hide_all():
    """Hides all widgets on the window."""
    for widget in root.winfo_children():
        widget.grid_remove()
        widget.pack_forget()
    
    for widget in input_frame.winfo_children():
        widget.grid_remove()
        widget.pack_forget()

# GUI Components
input_frame = ttk.LabelFrame(root)
btn_create_user = ttk.Button(root, text="Create Users", command=Load_Excel_Create)
btn_lock = ttk.Button(root, text="Lock Users", command=Load_Excel_Lock)
btn_ldap = ttk.Button(root, text="Add Domain Info", command=Add_Ldap)
lb_domain = ttk.Label(input_frame, text="Domain Server:", font=("Helvetica", 16))
lb_us_do = ttk.Label(input_frame, text="Username:", font=("Helvetica", 16))
lb_pas_do = ttk.Label(input_frame, text="Password:", font=("Helvetica", 16))
ent_domain = ttk.Entry(input_frame, font=("Helvetica", 16))
ent_us_do = ttk.Entry(input_frame, font=("Helvetica", 16))
ent_pas_do = ttk.Entry(input_frame, show="*", font=("Helvetica", 16))
btn_connect = ttk.Button(input_frame, text="Connect", command=Ldap)
lb_user = ttk.Label(input_frame, text="User NT:", font=("Helvetica", 16))
ent_user = ttk.Entry(input_frame, font=("Helvetica", 16))
lb_password = ttk.Label(input_frame, text="Password:", font=("Helvetica", 16))
ent_password = ttk.Entry(input_frame, show="*", font=("Helvetica", 16))
btn_user = ttk.Button(input_frame, text="Login", command=Check)
btn_auto = ttk.Button(input_frame, text="Auto", command=Auto_Page)
btn_group = ttk.Button(root, text="Group Users", command=Group_Page)
btn_reset = ttk.Button(input_frame, text="Reset Password", command=Reset)
btn_reset_page = ttk.Button(root, text="Reset Password", command=Reset_Page)
lb_user_nt = ttk.Label(input_frame, text="User NT:", font=("Helvetica", 16))
ent_user_nt = ttk.Entry(input_frame, font=("Helvetica", 16))
btn_home = ttk.Button(root, text="Home", command=Home_Display)
btn_admin_page = ttk.Button(root, text="Back", command=Admin_Page)
btn_logs = ttk.Button(root, text="Create Logs", command=Logs)
btn_reset_helpdesk_page = ttk.Button(root, text="Reset Password", command=Reset_Helpdesk_Page)
btn_reset_helpdesk = ttk.Button(input_frame, text="Reset Password", command=Reset_Helpdesk)
lb_sender_mail = ttk.Label(input_frame, text="Sender Mail: ", font=("Helvetica", 16))
ent_sender_mail = ttk.Entry(input_frame, font=("Helvetica", 16))
lb_reciever_mail = ttk.Label(input_frame, text='Reciever Mail: ', font=("Helvetica", 16))
ent_reciever_mail = ttk.Entry(input_frame, font=("Helvetica", 16))
lb_app_password = ttk.Label(input_frame, text='App Password: ',font=("Helvetica", 16))
ent_app_password = ttk.Entry(input_frame, font=("Helvetica", 16))
btn_helpdesk_page = ttk.Button(root, text="Back", command=HelpDesk)
btn_unlock_helpdesk_page = ttk.Button(root, text="Unlock User", command=Unlock_Helpdesk_Page)
btn_unlock = ttk.Button(input_frame, text="Unlock", command=unlock_user)
btn_unlock_admin_page = ttk.Button(root, text="Unlock User", command=Unlock_Admin_Page)
btn_create_group = ttk.Button(input_frame, text='Create', command=Group_Creation)
lb_group_name = ttk.Label(input_frame, text="Enter Group's Name: ", font=("Helvetica", 16))
ent_group_name = ttk.Entry(input_frame, font=("Helvetica", 16))
lb_group_type = ttk.Label(input_frame, text="Choose Group's Type: ", font=("Helvetica", 16))
lb_domain_host = ttk.Label(input_frame, text="Domain's Hostname: ", font=("Helvetica", 16))
ent_domain_host = ttk.Entry(input_frame, font=("Helvetica", 16))
btn_stop_auto = ttk.Button(input_frame,text='Stop Running',command=stop_function)
types = StringVar()
group_type = ttk.Combobox(input_frame, textvariable=types, font=("Helvetica", 16))
group_type['values'] = ('Security', 'Distribution')


# Initial Display
mycursor.execute("SELECT * FROM domain")
domain_data = mycursor.fetchall()
mycursor.execute("SELECT * FROM mail_server")
mail_data = mycursor.fetchall()
if not domain_data:
    First_Login()
else:
    domain, domain_user, domain_password, domain_host = domain_data[0]
    domain_parts = domain.split('.')
    dc1, dc2 = domain_parts[0], domain_parts[1]
    server = Server(domain, get_info=ALL)
    conn = Connection(server, user=f'{domain_user}@{domain}', password=domain_password, auto_bind=True)
    session = winrm.Session(domain_host, auth=('{}@{}'.format(domain_user,domain), domain_password), transport='ntlm')
    
    sender_email, receiver_email, mail_password = mail_data[0]

    Home_Display()

root.mainloop()

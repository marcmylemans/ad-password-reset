import configparser
import sys
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from ldap3 import Connection, NTLM

DEBUG_MODE = '--debug' in sys.argv or '-debug' in sys.argv
def debug_print(*args, **kwargs):
    if DEBUG_MODE:
        print(*args, **kwargs)
if DEBUG_MODE:
    print("!!! DEBUG MODE ENABLED !!!")

# --- Load config.ini ---
config = configparser.ConfigParser()
config.read('config.ini')
AD_SERVER     = config['ad']['server']
AD_DOMAIN     = config['ad']['domain']
AD_USER_OU    = config['ad']['user_ou']
RESET_GROUP   = config['ad']['reset_group']
NEW_PASSWORD  = config['ad']['new_password']
SVC_USERNAME  = config['service_account']['username']
SVC_PASSWORD  = config['service_account']['password']

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'  # Change this for production

# --- Audit Logging ---
AUDIT_LOG_PATH = 'audit.log'
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOG_PATH, encoding='utf-8')
audit_handler.setFormatter(logging.Formatter('%(message)s'))
audit_logger.addHandler(audit_handler)

def audit(action, user, target=None, extra=None):
    time_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    entry = {
        'timestamp': time_str,
        'action': action,
        'user': user,
        'target': target or '',
        'extra': extra or ''
    }
    logline = f"{entry['timestamp']},{entry['action']},{entry['user']},{entry['target']},{entry['extra']}"
    audit_logger.info(logline)
    debug_print(f"[AUDIT] {logline}")

def ad_connection():
    user = f'{AD_DOMAIN}\\{SVC_USERNAME}'
    debug_print(f"[ad_connection] Connecting to AD as {user}")
    try:
        c = Connection(AD_SERVER, user=user, password=SVC_PASSWORD, authentication=NTLM, auto_bind=True)
        return c
    except Exception as e:
        debug_print(f"[ad_connection] FAILED: {e}")
        return None

def is_user_in_group(username, groupname):
    debug_print(f"[is_user_in_group] Checking {username} in group {groupname}")
    c = ad_connection()
    if not c:
        debug_print("[is_user_in_group] Could not connect to AD")
        return False
    search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
    c.search(AD_USER_OU, search_filter, attributes=['memberOf'])
    if c.entries:
        memberships = c.entries[0]['memberOf']
        debug_print(f"[is_user_in_group] Groups for {username}: {memberships}")
        result = any(groupname.lower() in str(g).lower() for g in memberships)
        debug_print(f"[is_user_in_group] '{groupname}' in memberships? {result}")
        c.unbind()
        return result
    debug_print(f"[is_user_in_group] No entries for {username}")
    c.unbind()
    return False

def get_ad_users():
    debug_print(f"[get_ad_users] Listing users")
    c = ad_connection()
    if not c:
        debug_print("[get_ad_users] Could not connect to AD")
        return []
    c.search(
        AD_USER_OU,
        '(objectClass=user)',
        attributes=['sAMAccountName', 'employeeNumber', 'lockoutTime']
    )
    users = []
    for entry in c.entries:
        username = entry['sAMAccountName'].value
        employee_number = entry['employeeNumber'].value if 'employeeNumber' in entry and entry['employeeNumber'].value else ''
        lockout_value = entry['lockoutTime'].value if 'lockoutTime' in entry else None
        is_locked = False
        if lockout_value:
            # If it's a datetime object
            if hasattr(lockout_value, 'year'):
                # Unlocked accounts may have lockoutTime set to 1601-01-01 00:00:00
                # AD treats lockoutTime of Jan 1, 1601 as "not locked"
                is_locked = lockout_value.year > 1601
            # If it's a number
            elif isinstance(lockout_value, (int, float)):
                is_locked = lockout_value > 0
        users.append({
            'username': username,
            'employee_number': employee_number,
            'is_locked': is_locked
        })
    debug_print(f"[get_ad_users] Found users: {users}")
    c.unbind()
    return users




def reset_password(target_username, employee_number):
    debug_print(f"[reset_password] Attempting reset for: {target_username} with emp#: {employee_number}")
    c = ad_connection()
    if not c:
        debug_print("[reset_password] Could not connect to AD")
        return False, "Could not connect to AD"
    dn = None
    c.search(AD_USER_OU, f'(sAMAccountName={target_username})', attributes=['distinguishedName'])
    if c.entries:
        dn = c.entries[0]['distinguishedName'].value
        debug_print(f"[reset_password] Found DN: {dn}")
    else:
        debug_print(f"[reset_password] User {target_username} not found in OU {AD_USER_OU}")
        c.unbind()
        return False, "User not found"
    if dn:
        new_password = f"{NEW_PASSWORD}{employee_number}"
        # Encode password in UTF-16LE with quotes as required by AD
        pwd_value = f'"{new_password}"'.encode('utf-16-le')
        # Set unicodePwd directly (must be over LDAPS)
        result = c.modify(dn, {'unicodePwd': [(2, pwd_value)]})
        debug_print(f"[reset_password] modify unicodePwd result: {result} for {dn}")
        if result:
            # Set "must change password at next logon"
            change_flag = c.modify(dn, {'pwdLastSet': [(2, 0)]})
            debug_print(f"[reset_password] Set pwdLastSet=0 for {dn} (must change at next logon): {change_flag}")
            c.unbind()
            return True, ""
        else:
            debug_print(f"[reset_password] Password change failed: {c.result}")
            c.unbind()
            return False, f"Password reset failed: {c.result.get('message','Unknown error')}"
    c.unbind()
    return False, "Unknown error"


def unlock_user(target_username):
    debug_print(f"[unlock_user] Attempting unlock for: {target_username}")
    c = ad_connection()
    if not c:
        debug_print("[unlock_user] Could not connect to AD")
        return False, "Could not connect to AD"
    dn = None
    c.search(AD_USER_OU, f'(sAMAccountName={target_username})', attributes=['distinguishedName', 'lockoutTime'])
    if c.entries:
        dn = c.entries[0]['distinguishedName'].value
        debug_print(f"[unlock_user] Found DN: {dn}")
    else:
        debug_print(f"[unlock_user] User {target_username} not found in OU {AD_USER_OU}")
        c.unbind()
        return False, "User not found"
    if dn:
        result = c.modify(dn, {'lockoutTime': [(2, 0)]})
        debug_print(f"[unlock_user] modify lockoutTime result: {result} for {dn}, details: {c.result}")
        # Immediately re-read lockoutTime to verify
        c.search(AD_USER_OU, f'(sAMAccountName={target_username})', attributes=['lockoutTime'])
        lockout_value = c.entries[0]['lockoutTime'].value if c.entries else None
        c.unbind()
        is_locked = False
        if lockout_value:
            if hasattr(lockout_value, 'year'):
                # Only locked if year > 1601
                is_locked = lockout_value.year > 1601
            elif isinstance(lockout_value, (int, float)):
                is_locked = lockout_value > 0
        if is_locked:
            return False, "Unlock failed, account is still locked."
        return True, ""
    c.unbind()
    return False, "Unknown error"




@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        if '@' in username:
            flash('Please use your short AD username, not your email address.')
            debug_print(f"[login] UPN format detected: {username}")
            audit('login_failed', username, extra='UPN_format')
            return render_template('login.html')
        debug_print(f"[login] Login attempt for: {username}")
        audit('login_attempt', username, extra=request.remote_addr)
        if is_user_in_group(username, RESET_GROUP):
            session['user'] = username
            debug_print(f"[login] Login success for: {username}")
            audit('login_success', username, extra=request.remote_addr)
            return redirect(url_for('users'))
        else:
            flash('Login failed or insufficient permissions.')
            debug_print(f"[login] Login failed or insufficient permissions for: {username}")
            audit('login_failed', username, extra=request.remote_addr)
    return render_template('login.html')

@app.route('/users')
def users():
    if 'user' not in session:
        debug_print("[users] No session, redirect to login.")
        return redirect(url_for('login'))
    userlist = get_ad_users()
    debug_print(f"[users] Userlist: {userlist}")
    return render_template('users.html', users=userlist)

@app.route('/reset/<username>', methods=['POST'])
def reset(username):
    if 'user' not in session:
        debug_print("[reset] No session, redirect to login.")
        return redirect(url_for('login'))
    employee_number = request.form.get('employee_number', '')
    success, error_msg = reset_password(username, employee_number)
    if success:
        audit('reset_password', session['user'], target=username, extra=f"emp:{employee_number}")
        flash(f"Password for {username} has been reset.")
        debug_print(f"[reset] Password reset for {username} (emp#: {employee_number})")
    else:
        audit('reset_password_failed', session['user'], target=username, extra=error_msg)
        flash(f"Password reset failed for {username}: {error_msg}")
        debug_print(f"[reset] Password reset failed for {username}: {error_msg}")
    return redirect(url_for('users'))

@app.route('/unlock/<username>', methods=['POST'])
def unlock(username):
    if 'user' not in session:
        debug_print("[unlock] No session, redirect to login.")
        return redirect(url_for('login'))
    success, error_msg = unlock_user(username)
    if success:
        audit('unlock_account', session['user'], target=username)
        flash(f"Account for {username} has been unlocked.")
        debug_print(f"[unlock] Unlock for {username} succeeded")
    else:
        audit('unlock_account_failed', session['user'], target=username, extra=error_msg)
        flash(f"Account unlock failed for {username}: {error_msg}")
        debug_print(f"[unlock] Unlock for {username} failed: {error_msg}")
    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    audit('logout', session.get('user','?'))
    session.clear()
    debug_print("[logout] Session cleared.")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

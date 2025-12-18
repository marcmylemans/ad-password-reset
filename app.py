import os
import sys
import secrets
import configparser
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from ldap3 import Connection, NTLM
from ldap3.utils.conv import escape_filter_chars

# ------------------ Runtime flags ------------------

DEBUG_MODE = (
    "--debug" in sys.argv
    or "-debug" in sys.argv
    or os.getenv("DEBUG_MODE", "").lower() in ("1", "true", "yes", "on")
)

def debug_print(*args, **kwargs):
    if DEBUG_MODE:
        print(*args, **kwargs)

if DEBUG_MODE:
    print("!!! DEBUG MODE ENABLED !!!")

# ------------------ Config ------------------

config = configparser.ConfigParser()
config.read("config.ini")

AD_SERVER     = config["ad"]["server"]
AD_DOMAIN     = config["ad"]["domain"]
AD_USER_OU    = config["ad"]["user_ou"]
RESET_GROUP   = config["ad"]["reset_group"]
NEW_PASSWORD  = config["ad"]["new_password"]

SVC_USERNAME  = config["service_account"]["username"]
SVC_PASSWORD  = config["service_account"]["password"]

app = Flask(__name__)

# Secret key MUST be provided via env in non-debug runs
_env_secret = os.getenv("FLASK_SECRET_KEY")
if not _env_secret and not DEBUG_MODE:
    raise RuntimeError("Missing FLASK_SECRET_KEY environment variable (required in production).")
app.secret_key = _env_secret or secrets.token_hex(32)

# ------------------ Audit logging ------------------

AUDIT_LOG_PATH = "audit.log"
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(audit_handler)

def audit(action, user, target=None, extra=None):
    time_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = {
        "timestamp": time_str,
        "action": action,
        "user": user,
        "target": target or "",
        "extra": extra or "",
    }
    logline = f"{entry['timestamp']},{entry['action']},{entry['user']},{entry['target']},{entry['extra']}"
    audit_logger.info(logline)
    debug_print(f"[AUDIT] {logline}")

# ------------------ CSRF (simple, no extra deps) ------------------

def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

def require_csrf():
    sent = request.form.get("csrf_token", "")
    if not sent or sent != session.get("csrf_token"):
        abort(400)

# ------------------ LDAP helpers ------------------

def ad_connection():
    """Service account bind (for listing users / performing resets)."""
    user = f"{AD_DOMAIN}\\{SVC_USERNAME}"
    debug_print(f"[ad_connection] Connecting to AD as {user}")
    try:
        return Connection(
            AD_SERVER,
            user=user,
            password=SVC_PASSWORD,
            authentication=NTLM,
            auto_bind=True,
        )
    except Exception as e:
        debug_print(f"[ad_connection] FAILED: {e}")
        return None

def user_bind(username: str, password: str) -> bool:
    """End-user authentication: bind must succeed."""
    user = f"{AD_DOMAIN}\\{username}"
    try:
        c = Connection(
            AD_SERVER,
            user=user,
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )
        c.unbind()
        return True
    except Exception as e:
        debug_print(f"[user_bind] Failed for {username}: {e}")
        return False

def _group_match(memberof_dn: str, groupname: str) -> bool:
    """Match by full DN if RESET_GROUP looks like a DN, otherwise match CN exactly."""
    dn_l = (memberof_dn or "").lower()
    g_l = (groupname or "").lower()

    if "cn=" in g_l:
        return dn_l == g_l

    # Extract CN from DN
    # Example: CN=Password Resetters,OU=Groups,DC=example,DC=com
    m = memberof_dn.split(",")[0]
    if m.lower().startswith("cn="):
        cn = m[3:]
        return cn.lower() == g_l
    return False

def is_user_in_group(username: str, groupname: str) -> bool:
    debug_print(f"[is_user_in_group] Checking {username} in group {groupname}")
    c = ad_connection()
    if not c:
        debug_print("[is_user_in_group] Could not connect to AD")
        return False

    safe_username = escape_filter_chars(username)
    search_filter = f"(&(objectClass=user)(sAMAccountName={safe_username}))"

    c.search(AD_USER_OU, search_filter, attributes=["memberOf"])
    if c.entries:
        memberships = c.entries[0]["memberOf"]
        debug_print(f"[is_user_in_group] Groups for {username}: {memberships}")
        result = any(_group_match(str(g), groupname) for g in memberships)
        debug_print(f"[is_user_in_group] Match? {result}")
        c.unbind()
        return result

    debug_print(f"[is_user_in_group] No entries for {username}")
    c.unbind()
    return False

# ------------------ AD operations ------------------

def get_ad_users():
    debug_print("[get_ad_users] Listing users")
    c = ad_connection()
    if not c:
        debug_print("[get_ad_users] Could not connect to AD")
        return []

    c.search(
        AD_USER_OU,
        "(objectClass=user)",
        attributes=["sAMAccountName", "employeeNumber", "lockoutTime"],
    )

    users = []
    for entry in c.entries:
        username = entry["sAMAccountName"].value
        employee_number = entry["employeeNumber"].value if "employeeNumber" in entry and entry["employeeNumber"].value else ""
        lockout_value = entry["lockoutTime"].value if "lockoutTime" in entry else None

        is_locked = False
        if lockout_value:
            if hasattr(lockout_value, "year"):
                is_locked = lockout_value.year > 1601
            elif isinstance(lockout_value, (int, float)):
                is_locked = lockout_value > 0

        users.append(
            {
                "username": username,
                "employee_number": employee_number,
                "is_locked": is_locked,
            }
        )

    debug_print(f"[get_ad_users] Found users: {users}")
    c.unbind()
    return users

def reset_password(target_username: str):
    """
    Secure password logic:
    - Do NOT trust employee_number from the browser.
    - Pull employeeNumber from AD and append to NEW_PASSWORD.
    """
    debug_print(f"[reset_password] Attempting reset for: {target_username}")
    c = ad_connection()
    if not c:
        debug_print("[reset_password] Could not connect to AD")
        return False, "Could not connect to AD"

    safe_target = escape_filter_chars(target_username)
    c.search(
        AD_USER_OU,
        f"(sAMAccountName={safe_target})",
        attributes=["distinguishedName", "employeeNumber"],
    )

    if not c.entries:
        debug_print(f"[reset_password] User {target_username} not found in OU {AD_USER_OU}")
        c.unbind()
        return False, "User not found"

    dn = c.entries[0]["distinguishedName"].value
    employee_number = c.entries[0]["employeeNumber"].value if "employeeNumber" in c.entries[0] else None

    if not employee_number:
        c.unbind()
        return False, "employeeNumber missing in AD for this user"

    new_password = f"{NEW_PASSWORD}{employee_number}"
    pwd_value = f'"{new_password}"'.encode("utf-16-le")

    result = c.modify(dn, {"unicodePwd": [(2, pwd_value)]})
    debug_print(f"[reset_password] modify unicodePwd result: {result} for {dn}")

    if result:
        change_flag = c.modify(dn, {"pwdLastSet": [(2, 0)]})
        debug_print(f"[reset_password] Set pwdLastSet=0: {change_flag}")
        c.unbind()
        return True, ""
    else:
        msg = c.result.get("message", "Unknown error")
        debug_print(f"[reset_password] Password change failed: {c.result}")
        c.unbind()
        return False, f"Password reset failed: {msg}"

def unlock_user(target_username: str):
    debug_print(f"[unlock_user] Attempting unlock for: {target_username}")
    c = ad_connection()
    if not c:
        debug_print("[unlock_user] Could not connect to AD")
        return False, "Could not connect to AD"

    safe_target = escape_filter_chars(target_username)
    c.search(AD_USER_OU, f"(sAMAccountName={safe_target})", attributes=["distinguishedName"])
    if not c.entries:
        c.unbind()
        return False, "User not found"

    dn = c.entries[0]["distinguishedName"].value
    result = c.modify(dn, {"lockoutTime": [(2, 0)]})
    debug_print(f"[unlock_user] modify lockoutTime result: {result} for {dn}, details: {c.result}")

    # Verify immediately
    c.search(AD_USER_OU, f"(sAMAccountName={safe_target})", attributes=["lockoutTime"])
    lockout_value = c.entries[0]["lockoutTime"].value if c.entries else None
    c.unbind()

    is_locked = False
    if lockout_value:
        if hasattr(lockout_value, "year"):
            is_locked = lockout_value.year > 1601
        elif isinstance(lockout_value, (int, float)):
            is_locked = lockout_value > 0

    if is_locked:
        return False, "Unlock failed, account is still locked."
    return True, ""

# ------------------ Routes ------------------

@app.route("/", methods=["GET", "POST"])
def login():
    get_csrf_token()

    if request.method == "POST":
        require_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return render_template("login.html", csrf_token=session["csrf_token"])

        if "@" in username:
            flash("Please use your short AD username, not your email address.")
            debug_print(f"[login] UPN format detected: {username}")
            audit("login_failed", username, extra="UPN_format")
            return render_template("login.html", csrf_token=session["csrf_token"])

        debug_print(f"[login] Login attempt for: {username}")
        audit("login_attempt", username, extra=request.remote_addr)

        # 1) Authenticate via LDAP bind
        if not user_bind(username, password):
            flash("Login failed or insufficient permissions.")
            audit("login_failed", username, extra=f"{request.remote_addr}|bad_password")
            return render_template("login.html", csrf_token=session["csrf_token"])

        # 2) Authorize by group membership
        if not is_user_in_group(username, RESET_GROUP):
            flash("Login failed or insufficient permissions.")
            audit("login_failed", username, extra=f"{request.remote_addr}|not_in_group")
            return render_template("login.html", csrf_token=session["csrf_token"])

        session["user"] = username
        # rotate CSRF token after login
        session["csrf_token"] = secrets.token_urlsafe(32)

        debug_print(f"[login] Login success for: {username}")
        audit("login_success", username, extra=request.remote_addr)
        return redirect(url_for("users"))

    return render_template("login.html", csrf_token=session["csrf_token"])

@app.route("/users")
def users():
    if "user" not in session:
        debug_print("[users] No session, redirect to login.")
        return redirect(url_for("login"))

    userlist = get_ad_users()
    return render_template("users.html", users=userlist, csrf_token=get_csrf_token())

@app.route("/reset/<username>", methods=["POST"])
def reset(username):
    if "user" not in session:
        debug_print("[reset] No session, redirect to login.")
        return redirect(url_for("login"))

    require_csrf()

    success, error_msg = reset_password(username)
    if success:
        audit("reset_password", session["user"], target=username)
        flash(f"Password for {username} has been reset.")
        debug_print(f"[reset] Password reset for {username}")
    else:
        audit("reset_password_failed", session["user"], target=username, extra=error_msg)
        flash(f"Password reset failed for {username}: {error_msg}")
        debug_print(f"[reset] Password reset failed for {username}: {error_msg}")

    return redirect(url_for("users"))

@app.route("/unlock/<username>", methods=["POST"])
def unlock(username):
    if "user" not in session:
        debug_print("[unlock] No session, redirect to login.")
        return redirect(url_for("login"))

    require_csrf()

    success, error_msg = unlock_user(username)
    if success:
        audit("unlock_account", session["user"], target=username)
        flash(f"Account for {username} has been unlocked.")
        debug_print(f"[unlock] Unlocked {username}")
    else:
        audit("unlock_account_failed", session["user"], target=username, extra=error_msg)
        flash(f"Account unlock failed for {username}: {error_msg}")
        debug_print(f"[unlock] Unlock for {username} failed: {error_msg}")

    return redirect(url_for("users"))

@app.route("/logout")
def logout():
    audit("logout", session.get("user", "?"))
    session.clear()
    debug_print("[logout] Session cleared.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=DEBUG_MODE)

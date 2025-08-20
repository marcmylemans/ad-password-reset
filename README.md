# AD Password Reset Web Tool

A simple, secure, airgapped-friendly web app for delegated password resets in Microsoft Active Directory.  
Supports auditing, user verification by group, employee number-based password resets, and logging requirements.

---

## Features

- **Active Directory integration:** Uses a service account, never stores user credentials.
- **User login with AD group membership check.**
- **Reset passwords with employee number appended.**
- **Force user to change password at next logon.**
- **Modern, responsive web UI (pure CSS, no external dependencies).**
- **Audit log for every login, reset, and logout (CSV, local only).**
- **Works in airgapped environments.**
- **Designed for security and minimal privileges.**

---

## Requirements

- Python 3.8 or higher
- `flask` and `ldap3` Python packages
- LDAPS (Active Directory over SSL, port 636)
- A service account in Active Directory with delegated "Reset user passwords" rights on the user OU
- A service account in Active Directory with delegated "Read lockoutTime" rights on the user OU
- A service account in Active Directory with delegated "Write lockoutTime" rights on the user OU

---

## Setup

1. **Clone this repo and enter the directory:**

    ```sh
    git clone https://github.com/YourUsername/ad-password-reset.git
    cd ad-password-reset
    ```

2. **Install requirements:**

    ```sh
    pip install -r requirements.txt
    ```

3. **Configure your settings:**

    - Copy `config-sample.ini` to `config.ini` and edit:

        ```ini
        [ad]
        server = ldaps://yourdc.domain.local
        domain = YOURDOMAIN
        user_ou = OU=Users,DC=yourdomain,DC=local
        reset_group = Password Resetters
        new_password = YourStrongDefault!

        [service_account]
        username = svc_passwordreset
        password = YourSuperSecretPassword
        ```

4. **Run the app:**

    ```sh
    python app.py
    ```

5. **Open your browser:**  
   Visit [http://localhost:5000](http://localhost:5000)

---

## Security Notes

- **Never commit real credentials or audit logs.**
- Make sure your DC has a valid SSL certificate for LDAPS.
- Service account should be placed in a dedicated, secure OU.
- Delegate only the minimum required permissions.

---

## Audit Logging

All login attempts, password resets, and logouts are logged to `audit.log` in CSV format.  
Review and rotate logs as required by your policy.

---

## Customization

- UI templates are in the `templates/` folder.
- Employee numbers are hidden by default; click "Show" to reveal.
- Password policy is enforced by your AD domain settings.

---

## Disclaimer

This project is provided as-is for educational and internal use.  
Use at your own risk and review security before deploying in production.

---

## License

MIT License

---

## Author

Marc Mylemans

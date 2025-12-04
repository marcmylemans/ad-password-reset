
# AD Password Reset Tool


## 1. Purpose
This SOP explains installation, configuration, delegated AD permissions, and operational use of the **ad-password-reset** executable-based tool for password resets and account unlocks.

---

## 2. Delegated AD Permissions (Including Screenshots)

### Step 1 - Enable Advanced Features
In ADUC, enable 'Advanced Features'  
(View → Advanced Features).

![](steps-ad_password_reset___04_12_2025/step-0.png)

### Step 2 - Open Security Properties
Right‑click the OU → Properties → Security → Advanced.

![](steps-ad_password_reset___04_12_2025/step-1.png)

### Step 3 - Add Service Account
Click **Add** → select `svc_passwordreset`.

![](steps-ad_password_reset___04_12_2025/step-2.png)

### Step 4 - Apply ACL to Descendant User Objects
Set **Applies to:**  
**Descendant User Objects**

![](steps-ad_password_reset___04_12_2025/step-3.png)

### Step 5 - Enable Required Permissions
Enable:
- **Read lockoutTime**  
- **Write lockoutTime**

Apply changes and exit.

---

## 3. Create Service Account
Create an AD user account named for example:  
**svc_passwordreset**

![](steps-ad_password_reset___04_12_2025/step-4.png)

Ensure this account is placed in a secure OU and cannot log on interactively.

Also configure:  
`reset_group = AD group permitted to use the tool`

![](steps-ad_password_reset___04_12_2025/step-5.png)
![](steps-ad_password_reset___04_12_2025/step-6.png)

---

## 4. Configure Application (config.ini)
Copy `config-sample.ini` → `config.ini`.

Configure:

```
server = ldaps://<domaincontroller>
domain = YOURDOMAIN
user_ou = OU path containing user accounts
reset_group = <AD group allowed to use tool>
new_password = <temporary password>
```

Configure service account credentials under `[service_account]`.

![Config Screenshot](steps-ad_password_reset___04_12_2025/step-7.png)
![](steps-ad_password_reset___04_12_2025/step-8.png)
![](steps-ad_password_reset___04_12_2025/step-9.png)

---

## 5. Launch the Application
Run the executable:

```
app.exe
```

Open a browser:

```
http://<host>:5000
```

![Launching](steps-ad_password_reset___04_12_2025/step-10.png)

---

## 6. Operating Procedure

Navigate to:

```
http://<host>:5000
```

Login using an AD account that is a member of **reset_group**.

![Login](steps-ad_password_reset___04_12_2025/step-11.png)

Perform:

- Password reset (temporary password + force change)
- Unlock account (clears lockoutTime)

![](steps-ad_password_reset___04_12_2025/step-12.png)

---

## 7. Audit Logging
All activity is logged in `audit.log`.  
Archive and protect logs according to your policies.

![Audit Logging](steps-ad_password_reset___04_12_2025/step-13.png)

---


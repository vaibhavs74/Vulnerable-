# VulnLab — Intentional Vulnerability Practice Lab

Ek chhoti si Flask web app jisme bug bounty / VAPT practice ke liye
common web vulnerabilities **intentionally** daali gayi hain.

## ⚠️ Zaroori Warning

- **Sirf apne local machine ya isolated VM par chalao.** Internet par ya
  shared/office network par kabhi deploy mat karo — yeh app jaan-boojh kar
  insecure hai (koi input validation nahi, debug mode on, weak secret key).
- Sirf apne systems ya explicit permission wale targets par hi testing karo.
  Bina permission kisi third-party ki website/app par yeh techniques use
  karna illegal hai (India me IT Act 2000 ke under bhi punishable hai).
- Yeh ek learning sandbox hai — iska koi production use nahi hai.

## Login

The whole site sits behind a real, securely-implemented login
(hashed passwords, parameterized queries, server-side sessions).

```
admin   / Admin@123    (role: admin)
student / Student@123  (role: user)
```

## Modules Included

No hints are shown in the UI by design — approach each one like a real
target and figure out the bug class yourself (or open `app.py` once you're
ready to check).

| Module | URL |
|---|---|
| Account Login (secondary form) | `/sqli-login` |
| Product Search | `/sqli-search` |
| Profile Greeting | `/xss-reflected` |
| Guestbook | `/xss-stored` |
| Network Diagnostics | `/cmdi` |
| Account Lookup | `/idor` |
| Document Upload | `/upload` |
| Preferences | `/broken-auth` |
| Two-Factor Verification (OTP) | `/otp` |
| Store Checkout | `/checkout` |
| Order History | `/orders` |
| My Vault (correctly secured example) | `/account/vault` |

### About the OTP module
The OTP is never shown on the page. It is "delivered" by appending a line
to `otp_log.txt` in this folder (and printed to the server console) —
this file stands in for a real SMS/email gateway, which this lab never
actually contacts. No real phone number, email, or third-party API is
used anywhere.

### About the Checkout module
This is a fully simulated payment flow. No real payment gateway (Razorpay,
Stripe, etc.) is ever contacted, no real card is validated, and no real
money moves. "Orders" are just rows in the local SQLite database.

## Setup (Local)

Requires Python 3.9+.

```bash
cd vulnlab
pip install -r requirements.txt
python database.py      # creates lab.db with sample data
python app.py            # starts server at http://127.0.0.1:5000
```

Browser me kholo: **http://127.0.0.1:5000**

## Tools to pair with this lab

- **Burp Suite Community** — intercept/modify requests
- **OWASP ZAP** — automated + manual scanning
- **sqlmap** — automate the SQLi modules (`sqlmap -u "http://127.0.0.1:5000/sqli-search?q=test"`)
- **curl / Postman** — manual request crafting

## Resetting the lab

Agar data mess ho jaye (jaise stored XSS entries ya uploaded files),
bas dobara chala do:

```bash
python database.py
```

aur `uploads/` folder ke andar files manually delete kar do agar chahiye.

## Suggested practice flow

1. Pehle bina kisi hint ke khud se bug dhoondo (black-box style).
2. Phir `app.py` kholke dekho vulnerability code me kaha hai.
3. Ek "fixed" version likhne ki koshish karo (parameterized queries,
   `escape()`/Jinja auto-escaping, allow-listed file extensions, signed
   sessions with `flask-login` ya JWT, `subprocess` without `shell=True`
   and with arg lists, etc.) — yehi asli VAPT/bug-bounty skill hai:
   dhoondhna aur sahi fix sujhana dono.

Happy (ethical) hacking! 🛡️

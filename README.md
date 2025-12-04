# Instagram Security Scanner 🔐

A simple Python CLI tool that performs a **basic security check** on **your own Instagram account**.

It checks:

- Local password strength (length & complexity)
- Whether Two-Factor Authentication (2FA) appears to be enabled
- Whether your recovery email and phone are set
- Basic account privacy (public/private) — best-effort
- General security recommendations (login activity, connected apps, email security)

> ⚠ **IMPORTANT**
> - For **your own account only**.
> - Runs locally on your machine.
> - Never share this script (with your password) with anyone.
> - This is **not** an official Instagram tool and may break if Instagram changes their UI.

---

## 🚀 Features

- Asks for your **username** and **password** via terminal  
- Opens Chrome using Selenium  
- You complete any 2FA / prompts in the browser  
- Generates a **console report** with:
  - ✅ OK items
  - ⚠ WARN items
  - ℹ Info/manual checks

---

## 🧰 Requirements

- Python 3.8+
- Google Chrome
- `pip` to install Python packages
- Works well on **Ubuntu + Chrome** (other OSes may also work with small tweaks)

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/R3DDR4G0N/instagram-security-scanner.git
cd instagram-security-scanner
python3 insta_full_security_scan.py

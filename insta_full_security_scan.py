import os
import string
import time
from datetime import datetime
from getpass import getpass
import importlib.util
import glob

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from colorama import init, Fore, Style

# Initialize colorama (for Windows & Linux)
init(autoreset=True)


# ================== Utils ==================

def clear_screen():
    # Clear terminal for clean hacker look
    os.system("clear")


def boot_sequence():
    steps = [
        "[BOOT] Initializing Dragon Core...",
        "[BOOT] Loading Instagram Security Modules...",
        "[BOOT] Module: Password Scanner .......... OK",
        "[BOOT] Module: 2FA Checker ............... OK",
        "[BOOT] Module: Privacy Analyzer .......... OK",
        "[BOOT] Module: Breach Scanner ............ OK",
        "[BOOT] Module: Plugin Engine ............. OK",
        "[BOOT] All systems online. Welcome, Dragon."
    ]
    for line in steps:
        print(Fore.GREEN + line + Style.RESET_ALL)
        time.sleep(0.25)
    print()
    time.sleep(0.3)


# ================== Banner ==================

def print_banner():
    border = Fore.GREEN + "###############################################"
    title = Fore.CYAN + "#        INSTAGRAM SECURITY SUITE             #"
    byline = Fore.MAGENTA + "#             MADE BY DRAGON 🐉               #"
    print("\n" + border)
    print(title)
    print(byline)
    print(border + Style.RESET_ALL)


# ================== WebDriver Setup (Ubuntu + Chrome) ==================

def create_driver(headless=False):
    """
    Create and return a Chrome WebDriver instance.
    Uses Selenium Manager (Selenium 4.6+) to auto-manage chromedriver.
    """
    options = webdriver.ChromeOptions()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--disable-notifications")
    options.add_argument("--start-maximized")
    return webdriver.Chrome(options=options)


# ================== Data Structures ==================

class Finding:
    """
    Represents one security finding in the report.
    level: "OK", "WARN", "INFO"
    """

    def __init__(self, level, title, details=""):
        self.level = level
        self.title = title
        self.details = details

    def __str__(self):
        # Plain text version (used for export / non-colored)
        prefix = {"OK": "✅", "WARN": "⚠", "INFO": "ℹ"}.get(self.level, "•")
        if self.details:
            return f"{prefix} {self.title}\n    {self.details}"
        return f"{prefix} {self.title}"


class SecurityReport:
    """
    Holds all findings and can render them nicely or export them.
    """

    def __init__(self):
        self.findings = []

    def add(self, level, title, details=""):
        self.findings.append(Finding(level, title, details))

    def extend(self, findings):
        self.findings.extend(findings)

    def is_empty(self):
        return len(self.findings) == 0

    def compute_score(self):
        """
        Very simple security score from 0–100 based on WARN/OK findings.
        This is just heuristic for fun.
        """
        if not self.findings:
            return 0

        base = 100
        for f in self.findings:
            if f.level == "WARN":
                base -= 20
        if base < 0:
            base = 0
        if base > 100:
            base = 100
        return base

    def render_plain(self):
        """
        Return a plain multi-line string (no colors) for export.
        """
        lines = []
        lines.append("=============== INSTAGRAM SECURITY REPORT ===============")
        score = self.compute_score()
        lines.append(f"\nSecurity Score: {score}/100")
        if score >= 80:
            lines.append("Overall: Good – your account is fairly well protected.")
        elif score >= 50:
            lines.append("Overall: Medium – there is room to improve your security.")
        else:
            lines.append("Overall: Weak – you should fix the WARN items soon.")

        levels = ["WARN", "OK", "INFO"]
        labels = {
            "WARN": "IMPORTANT ISSUES",
            "OK": "Good",
            "INFO": "Info / Manual checks",
        }

        for lvl in levels:
            subset = [f for f in self.findings if f.level == lvl]
            if not subset:
                continue
            lines.append(f"\n--- {labels[lvl]} ---")
            for f in subset:
                lines.append(str(f))

        lines.append(
            "\nNote: This tool is a helper, not a perfect scanner. "
            "Always double-check security settings manually inside Instagram."
        )
        lines.append("=========================================================")
        return "\n".join(lines)

    def render_html(self):
        """
        Return an HTML string report with basic styling.
        """
        score = self.compute_score()
        if score >= 80:
            score_color = "#22c55e"  # green
            overall = "Good – your account is fairly well protected."
        elif score >= 50:
            score_color = "#eab308"  # yellow
            overall = "Medium – there is room to improve your security."
        else:
            score_color = "#ef4444"  # red
            overall = "Weak – you should fix the WARN items soon."

        def section_html(title, color, findings):
            if not findings:
                return ""
            items = ""
            for f in findings:
                icon = {"OK": "✅", "WARN": "⚠️", "INFO": "ℹ️"}.get(f.level, "•")
                items += f"""
                <div class="finding">
                    <div class="finding-title">{icon} {f.title}</div>
                    <div class="finding-details">{f.details}</div>
                </div>
                """
            return f"""
            <section>
                <h2 style="color:{color}">{title}</h2>
                {items}
            </section>
            """

        warn_findings = [f for f in self.findings if f.level == "WARN"]
        ok_findings = [f for f in self.findings if f.level == "OK"]
        info_findings = [f for f in self.findings if f.level == "INFO"]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Instagram Security Report</title>
<style>
body {{
    background-color: #020617;
    color: #e5e7eb;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    padding: 20px 24px;
}}
h1 {{
    color: #22c55e;
    margin-bottom: 0.2rem;
}}
h2 {{
    margin-top: 1.5rem;
    margin-bottom: 0.5rem;
}}
.card {{
    background-color: #0b1220;
    border-radius: 12px;
    padding: 16px 20px;
    margin-top: 16px;
    border: 1px solid #1f2937;
}}
.badge {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 0.8rem;
    margin-left: 8px;
}}
.badge-good {{ background-color: #16a34a33; color: #4ade80; }}
.badge-medium {{ background-color: #eab30833; color: #fde047; }}
.badge-bad {{ background-color: #dc262633; color: #fca5a5; }}
.finding {{
    padding: 6px 0;
}}
.finding-title {{
    font-weight: 600;
}}
.finding-details {{
    font-size: 0.9rem;
    color: #9ca3af;
    margin-left: 1.25rem;
}}
.footer {{
    margin-top: 2rem;
    font-size: 0.8rem;
    color: #6b7280;
}}
</style>
</head>
<body>
<h1>Instagram Security Report</h1>
<div class="card">
    <div>Security Score:
        <span style="color:{score_color}; font-weight:700;">{score}/100</span>
    </div>
    <div>{overall}</div>
    <div class="badge badge-medium">Generated by Dragon Security Suite 🐉</div>
</div>

{section_html("⚠ Important Issues", "#f97316", warn_findings)}
{section_html("✅ Good", "#22c55e", ok_findings)}
{section_html("ℹ Info / Manual Checks", "#38bdf8", info_findings)}

<div class="footer">
    Note: This report is a helper, not a perfect scanner.
    Always double-check security settings manually in the Instagram app/website.
</div>
</body>
</html>
"""
        return html

    def print_colored(self):
        """
        Pretty-print the report with colors for a hacker-style terminal feel.
        """
        score = self.compute_score()

        print(Fore.YELLOW + "=============== 🔐 INSTAGRAM SECURITY REPORT ===============")
        # Score color
        if score >= 80:
            score_color = Fore.GREEN
            overall = "✅ Good – your account is fairly well protected."
        elif score >= 50:
            score_color = Fore.YELLOW
            overall = "⚠ Medium – there is room to improve your security."
        else:
            score_color = Fore.RED
            overall = "🔥 Weak – you should fix the WARN items soon."

        print(score_color + f"\nSecurity Score: {score}/100")
        print(score_color + overall + Style.RESET_ALL)

        levels = ["WARN", "OK", "INFO"]
        labels = {
            "WARN": Fore.RED + "⚠ IMPORTANT ISSUES",
            "OK": Fore.GREEN + "✅ Good",
            "INFO": Fore.CYAN + "ℹ Info / Manual checks",
        }

        for lvl in levels:
            subset = [f for f in self.findings if f.level == lvl]
            if not subset:
                continue

            print("\n" + labels[lvl] + Style.RESET_ALL)
            for f in subset:
                if f.level == "WARN":
                    base_color = Fore.RED
                elif f.level == "OK":
                    base_color = Fore.GREEN
                else:
                    base_color = Fore.CYAN

                prefix = {"OK": "✅", "WARN": "⚠", "INFO": "ℹ"}.get(f.level, "•")
                print(base_color + f"{prefix} {f.title}")
                if f.details:
                    print(Fore.WHITE + "    " + f.details)

        print(
            Fore.MAGENTA
            + "\nNote: This tool is a helper, not a perfect scanner. "
              "Always double-check security settings manually inside Instagram."
        )
        print(Fore.YELLOW + "===========================================================" + Style.RESET_ALL)


# ================== Local Checks (no Instagram needed) ==================

def check_password_strength(password):
    """
    Local password strength check.
    We already have the password for login.
    We never print the password itself, only its strength.
    """
    findings = []

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = 0
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if has_lower and has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_symbol:
        score += 1

    if score <= 2:
        findings.append(Finding(
            "WARN",
            "Password looks WEAK.",
            "Use at least 16 characters with upper, lower, digits and symbols. "
            "Never reuse this password on other sites."
        ))
    elif score in (3, 4):
        findings.append(Finding(
            "INFO",
            "Password is average.",
            "You can make it stronger (more length + all character types)."
        ))
    else:
        findings.append(Finding(
            "OK",
            "Password looks STRONG.",
            "Remember to store it in a password manager."
        ))

    return findings


# ================== Instagram Automation Checks ==================

def login(driver, username, password):
    """
    Log into Instagram using Selenium.
    User must complete any 2FA / security prompts manually.
    """
    print(Fore.YELLOW + "\n[+] Opening Instagram login page..." + Style.RESET_ALL)
    driver.get("https://www.instagram.com/accounts/login/")
    wait = WebDriverWait(driver, 25)

    # Try cookie banner (will fail silently if not present)
    try:
        cookie_btn = wait.until(
            EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(.,'Allow') or contains(.,'Accept')]")
            )
        )
        cookie_btn.click()
        time.sleep(2)
    except Exception:
        pass

    user_input = wait.until(EC.presence_of_element_located((By.NAME, "username")))
    pass_input = driver.find_element(By.NAME, "password")

    user_input.clear()
    user_input.send_keys(username)
    pass_input.clear()
    pass_input.send_keys(password)

    login_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
    print(Fore.YELLOW + "[+] Submitting login form..." + Style.RESET_ALL)
    login_btn.click()

    print(
        Fore.CYAN
        + "\nIf Instagram shows 2FA / ‘Save login info’ / ‘Turn on notifications’,"
          "\nhandle it in the browser window."
        + Style.RESET_ALL
    )
    time.sleep(12)
    input(Fore.MAGENTA + "➡ When you are fully logged in (see your feed/profile), press Enter here to continue... " + Style.RESET_ALL)


def check_2fa(driver):
    """
    Roughly detect whether 2FA is enabled by inspecting the 2FA settings page.
    Instagram may change this UI anytime, so this is best-effort only.
    """
    findings = []
    print(Fore.YELLOW + "\n[+] Checking 2FA status..." + Style.RESET_ALL)
    driver.get("https://www.instagram.com/accounts/two_factor_authentication/")
    time.sleep(5)

    source = driver.page_source.lower()

    if "turn off" in source and "two-factor" in source:
        findings.append(Finding(
            "OK",
            "Two-Factor Authentication (2FA) seems ENABLED.",
            "Good! Keep backup codes somewhere safe."
        ))
    elif "turn on two-factor authentication" in source or "get started" in source:
        findings.append(Finding(
            "WARN",
            "2FA appears DISABLED.",
            "Turn it on: Settings → Security → Two-Factor Authentication. Prefer an authenticator app."
        ))
    else:
        findings.append(Finding(
            "INFO",
            "Could not clearly detect 2FA status.",
            "Instagram UI may have changed. Manually check: Settings → Security → Two-Factor Authentication."
        ))

    return findings


def check_email_phone(driver):
    """
    Check if email and phone number are set on the account
    by visiting the Edit Profile page.
    """
    findings = []
    print(Fore.YELLOW + "\n[+] Checking email & phone..." + Style.RESET_ALL)
    driver.get("https://www.instagram.com/accounts/edit/")
    wait = WebDriverWait(driver, 20)
    time.sleep(5)

    email = ""
    phone = ""

    try:
        email_input = wait.until(
            EC.presence_of_element_located((By.NAME, "email"))
        )
        email = email_input.get_attribute("value") or ""
    except Exception:
        findings.append(Finding(
            "INFO",
            "Could not read email field automatically.",
            "Check manually in Edit Profile."
        ))

    try:
        phone_input = driver.find_element(By.NAME, "phone_number")
        phone = phone_input.get_attribute("value") or ""
    except Exception:
        findings.append(Finding(
            "INFO",
            "Could not read phone number field automatically.",
            "Check manually in Edit Profile."
        ))

    if email:
        findings.append(Finding(
            "OK",
            "Recovery email is set.",
            f"Email: {email}"
        ))
    else:
        findings.append(Finding(
            "WARN",
            "No email detected on your account.",
            "Add a valid email for password recovery."
        ))

    if phone:
        findings.append(Finding(
            "OK",
            "Phone number is set.",
            f"Phone: {phone}"
        ))
    else:
        findings.append(Finding(
            "INFO",
            "No phone number detected.",
            "Optional, but adding a phone number can help with recovery."
        ))

    return findings


def check_privacy(driver):
    """
    Best-effort check of account privacy from the Privacy & Security settings page.
    """
    findings = []
    print(Fore.YELLOW + "\n[+] Checking if account is Private or Public..." + Style.RESET_ALL)
    driver.get("https://www.instagram.com/accounts/privacy_and_security/")
    time.sleep(5)

    src = driver.page_source.lower()

    if "private account" in src:
        if "on" in src and "private account" in src:
            findings.append(Finding(
                "OK",
                "Account is likely PRIVATE.",
                "People must follow you to see your posts."
            ))
        elif "off" in src and "private account" in src:
            findings.append(Finding(
                "INFO",
                "Account is likely PUBLIC.",
                "Anyone can see your posts and stories. Make it private if you want more privacy."
            ))
        else:
            findings.append(Finding(
                "INFO",
                "Found ‘Private account’ setting but not clear if ON/OFF.",
                "Please visually check the toggle in Privacy & Security settings."
            ))
    else:
        findings.append(Finding(
            "INFO",
            "Could not locate ‘Private account’ setting automatically.",
            "Manually check: Settings → Privacy → Account Privacy."
        ))

    return findings


def check_login_activity(driver):
    """
    Helper that opens login activity and asks the user
    if they saw any unknown devices/locations.
    """
    findings = []
    print(Fore.YELLOW + "\n[+] Opening Login Activity page..." + Style.RESET_ALL)
    # URL may change; this is best-effort
    driver.get("https://www.instagram.com/session/login_activity/")
    time.sleep(7)

    print(
        Fore.CYAN
        + "\nLook at the browser: review the list of devices/locations."
          "\nCheck if anything looks unknown or suspicious."
        + Style.RESET_ALL
    )
    answer = input(Fore.MAGENTA + "Did you see any device/location you DON'T recognize? (y/n): " + Style.RESET_ALL).strip().lower()
    if answer == "y":
        findings.append(Finding(
            "WARN",
            "Suspicious login activity reported.",
            "Log out from unknown devices in Login Activity and change your password."
        ))
    else:
        findings.append(Finding(
            "OK",
            "Login activity seems clean (based on your review).",
            "Keep checking Login Activity regularly."
        ))
    return findings


def manual_security_recommendations():
    findings = []
    findings.append(Finding(
        "INFO",
        "Review Login Activity regularly.",
        "In the app: Settings → Security → Login Activity. "
        "Log out from devices/locations you don't recognize."
    ))
    findings.append(Finding(
        "INFO",
        "Check connected apps & websites.",
        "Settings → Security → Apps and Websites. "
        "Remove things you don't use or don't trust."
    ))
    findings.append(Finding(
        "INFO",
        "Protect your EMAIL account.",
        "Your email can reset your Instagram password. "
        "Use a strong password + 2FA on email too."
    ))
    findings.append(Finding(
        "INFO",
        "Avoid phishing links.",
        "Never type your Instagram password on random websites or 'free follower' tools."
    ))
    return findings


# ================== Extra Features ==================

def run_breach_scan():
    """
    Check if an email appears in known breaches using HaveIBeenPwned-style API.
    Requires user to provide their own API key.
    """
    print(Fore.CYAN + "\n=== DATA BREACH SCAN (EMAIL) ===" + Style.RESET_ALL)
    email = input("Enter your email (the one used for Instagram or others): ").strip()
    if not email:
        print(Fore.RED + "No email entered. Aborting breach scan." + Style.RESET_ALL)
        return None

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        print(
            Fore.YELLOW
            + "\nNo HIBP API key found in environment (HIBP_API_KEY)."
              "\nYou need an API key from https://haveibeenpwned.com/API/Key"
            + Style.RESET_ALL
        )
        api_key = input("Paste your HIBP API key here (or leave blank to cancel): ").strip()
        if not api_key:
            print(Fore.RED + "No API key provided. Skipping breach scan." + Style.RESET_ALL)
            return None

    # Build request
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "DragonSecuritySuite/1.0"
    }
    params = {
        "truncateResponse": "true"
    }

    print(Fore.YELLOW + "\n[+] Contacting HaveIBeenPwned API..." + Style.RESET_ALL)

    report = SecurityReport()
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 404:
            # No breach for that account
            print(Fore.GREEN + "No breaches found for this email (according to HIBP)." + Style.RESET_ALL)
            report.add(
                "OK",
                "No known breaches for this email (HIBP).",
                "Still, avoid reusing passwords across sites."
            )
        elif resp.status_code == 200:
            breaches = resp.json()
            names = [b.get("Name", "Unknown") for b in breaches]
            print(Fore.RED + f"\n⚠ This email appears in {len(names)} breach(es):" + Style.RESET_ALL)
            for name in names:
                print(Fore.RED + f" - {name}" + Style.RESET_ALL)
            report.add(
                "WARN",
                f"Email found in {len(names)} known breach(es) (HIBP).",
                "Change passwords for breached services and do NOT reuse the same password on Instagram."
            )
        else:
            print(Fore.RED + f"Unexpected response from HIBP API: {resp.status_code}" + Style.RESET_ALL)
            report.add(
                "INFO",
                "Could not complete breach scan.",
                f"HIBP API returned status code {resp.status_code}."
            )
    except Exception as e:
        print(Fore.RED + f"Error contacting HIBP API: {e}" + Style.RESET_ALL)
        report.add(
            "INFO",
            "Error during breach scan.",
            str(e)
        )

    report.print_colored()
    return report


def run_backup_analysis():
    """
    Very simple analysis of Instagram data export folder.
    Just checks for presence of key JSON files and warns/reminds user.
    """
    print(Fore.CYAN + "\n=== INSTAGRAM BACKUP ANALYZER (BASIC) ===" + Style.RESET_ALL)
    path = input("Enter path to your extracted Instagram data folder (or leave blank to cancel): ").strip()
    if not path:
        print(Fore.RED + "No path provided, skipping backup analysis." + Style.RESET_ALL)
        return None

    if not os.path.isdir(path):
        print(Fore.RED + "Path does not exist or is not a directory." + Style.RESET_ALL)
        return None

    report = SecurityReport()

    personal_info = os.path.join(path, "personal_information", "personal_information.json")
    posts_1 = os.path.join(path, "content", "posts_1.json")
    media = os.path.join(path, "media", "media.json")

    found_any = False

    if os.path.exists(personal_info):
        found_any = True
        report.add(
            "INFO",
            "Personal information JSON found in backup.",
            "This file may contain profile info, contact details, etc. Keep your backup folder private."
        )
    if os.path.exists(posts_1) or os.path.exists(media):
        found_any = True
        report.add(
            "INFO",
            "Posts/media JSON found in backup.",
            "Your backup includes detailed data about your posts. Store it securely and encrypt if possible."
        )

    if not found_any:
        report.add(
            "INFO",
            "No standard JSON files detected.",
            "Backup structure might be different or incomplete. Check the folder manually."
        )

    # Fake 'attack surface' style summary
    report.add(
        "INFO",
        "Backup data security.",
        "Anyone with access to this backup can learn a lot about your activity. Treat it like a password vault."
    )

    report.print_colored()
    return report


def run_firewall_simulation():
    """
    Pure cosmetic 'system security' check (local machine),
    just prints messages. Does NOT really scan or hack anything.
    """
    print(Fore.CYAN + "\n=== LOCAL SECURITY SIMULATION (FIREWALL & BROWSER) ===" + Style.RESET_ALL)
    time.sleep(0.5)

    lines = [
        "[SCAN] Checking OS-level firewall....... OK",
        "[SCAN] Checking browser sandboxing...... OK",
        "[SCAN] Checking HTTPS enforcement....... OK",
        "[SCAN] Checking password manager usage.. UNKNOWN (user dependent)",
    ]
    for line in lines:
        color = Fore.GREEN if "OK" in line else Fore.YELLOW
        print(color + line + Style.RESET_ALL)
        time.sleep(0.25)

    print(Fore.MAGENTA + "\nNote: This is a cosmetic simulation, not a real system scan." + Style.RESET_ALL)


def run_plugins(report):
    """
    Simple plugin engine. Loads *.py from ./plugins and calls run_plugin(report)
    if present. Plugins can read or modify the report.
    """
    print(Fore.CYAN + "\n=== PLUGIN ENGINE ===" + Style.RESET_ALL)
    plugin_dir = "plugins"

    if not os.path.isdir(plugin_dir):
        print(Fore.YELLOW + "No 'plugins' directory found. Create ./plugins and add .py files with a run_plugin(report) function." + Style.RESET_ALL)
        return

    plugin_files = glob.glob(os.path.join(plugin_dir, "*.py"))
    if not plugin_files:
        print(Fore.YELLOW + "No plugins (*.py) found in ./plugins." + Style.RESET_ALL)
        return

    print(Fore.GREEN + f"Found {len(plugin_files)} plugin(s):" + Style.RESET_ALL)
    for pf in plugin_files:
        print(" - " + os.path.basename(pf))

    for pf in plugin_files:
        try:
            spec = importlib.util.spec_from_file_location("plugin_module", pf)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            if hasattr(mod, "run_plugin"):
                print(Fore.YELLOW + f"\n[PLUGIN] Running {os.path.basename(pf)}..." + Style.RESET_ALL)
                mod.run_plugin(report)
            else:
                print(Fore.RED + f"[PLUGIN] {os.path.basename(pf)} has no run_plugin(report) function, skipping." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[PLUGIN] Error running {os.path.basename(pf)}: {e}" + Style.RESET_ALL)


# ================== High-Level Flows (Menu Actions) ==================

def run_full_scan():
    """
    Ask for username & password, run full scan, return SecurityReport.
    """
    print(Fore.CYAN + "\n=== FULL INSTAGRAM SECURITY SCAN ===" + Style.RESET_ALL)
    username = input("Enter your Instagram username: ").strip()
    password = getpass("Enter your Instagram password (hidden): ")

    report = SecurityReport()
    report.extend(check_password_strength(password))

    driver = create_driver(headless=False)

    try:
        login(driver, username, password)
        report.extend(check_2fa(driver))
        report.extend(check_email_phone(driver))
        report.extend(check_privacy(driver))
        report.extend(check_login_activity(driver))
        report.extend(manual_security_recommendations())
    finally:
        choice = input(Fore.MAGENTA + "\nPress Enter to close browser, or type 'keep' to leave it open: " + Style.RESET_ALL).strip()
        if choice.lower() != "keep":
            driver.quit()

    print(Fore.GREEN + "\nScan completed.\n" + Style.RESET_ALL)
    report.print_colored()
    return report


def run_password_check_only():
    print(Fore.CYAN + "\n=== PASSWORD STRENGTH CHECK ===" + Style.RESET_ALL)
    password = getpass("Enter your Instagram password (or similar) to evaluate (hidden): ")

    report = SecurityReport()
    report.extend(check_password_strength(password))

    print(Fore.GREEN + "\nPassword check result:\n" + Style.RESET_ALL)
    report.print_colored()
    return report


def show_general_tips():
    print(Fore.CYAN + "\n=== GENERAL INSTAGRAM SECURITY TIPS ===\n" + Style.RESET_ALL)
    tips_report = SecurityReport()
    tips_report.extend(manual_security_recommendations())
    tips_report.print_colored()
    return tips_report


def export_report_to_txt(report):
    if report is None or report.is_empty():
        print(Fore.RED + "\nNo report available to export. Run a scan first." + Style.RESET_ALL)
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"insta_security_report_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report.render_plain())
        f.write("\n")

    print(Fore.GREEN + f"\nTXT report exported to: {filename}" + Style.RESET_ALL)


def export_report_to_html(report):
    if report is None or report.is_empty():
        print(Fore.RED + "\nNo report available to export. Run a scan first." + Style.RESET_ALL)
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"insta_security_report_{timestamp}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report.render_html())

    print(Fore.GREEN + f"\nHTML report exported to: {filename}" + Style.RESET_ALL)


# ================== CLI Menu ==================

def print_menu():
    print_banner()
    print(Fore.YELLOW + "1)" + Fore.WHITE + " Full security scan (login + settings check)")
    print(Fore.YELLOW + "2)" + Fore.WHITE + " Password strength check only (local)")
    print(Fore.YELLOW + "3)" + Fore.WHITE + " Show general security tips")
    print(Fore.YELLOW + "4)" + Fore.WHITE + " Export last report to TXT")
    print(Fore.YELLOW + "5)" + Fore.WHITE + " Export last report to HTML")
    print(Fore.YELLOW + "6)" + Fore.WHITE + " Data breach scan (email via HIBP)")
    print(Fore.YELLOW + "7)" + Fore.WHITE + " Analyze Instagram data export (basic)")
    print(Fore.YELLOW + "8)" + Fore.WHITE + " Local security simulation (firewall/browser)")
    print(Fore.YELLOW + "9)" + Fore.WHITE + " Run plugins (./plugins/*.py)")
    print(Fore.YELLOW + "0)" + Fore.WHITE + " Exit")
    print(Fore.GREEN + "==========================================================" + Style.RESET_ALL)


def main():
    clear_screen()  # clear old terminal stuff for clean hacker feel
    boot_sequence()

    last_report = None

    while True:
        print_menu()
        choice = input(Fore.CYAN + "Select option: " + Style.RESET_ALL).strip()

        if choice == "1":
            last_report = run_full_scan()
        elif choice == "2":
            last_report = run_password_check_only()
        elif choice == "3":
            last_report = show_general_tips()
        elif choice == "4":
            export_report_to_txt(last_report)
        elif choice == "5":
            export_report_to_html(last_report)
        elif choice == "6":
            breach_report = run_breach_scan()
            # combine breach result into last_report if both exist
            if breach_report:
                if last_report is None:
                    last_report = breach_report
                else:
                    last_report.extend(breach_report.findings)
        elif choice == "7":
            backup_report = run_backup_analysis()
            if backup_report:
                if last_report is None:
                    last_report = backup_report
                else:
                    last_report.extend(backup_report.findings)
        elif choice == "8":
            run_firewall_simulation()
        elif choice == "9":
            if last_report is None:
                last_report = SecurityReport()
            run_plugins(last_report)
        elif choice == "0":
            print(Fore.MAGENTA + "\nGoodbye. Stay safe online 🛡️" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)


if __name__ == "__main__":
    main()

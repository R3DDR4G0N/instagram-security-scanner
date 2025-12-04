import string
import time
from datetime import datetime
from getpass import getpass

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# ================== Banner ==================

def print_banner():
    print(r"""
###############################################
#        INSTAGRAM SECURITY SUITE             #
#             MADE BY DRAGON 🐉               #
###############################################
""")


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

    def render(self):
        """
        Return a multi-line string for console/report.
        """
        lines = []
        lines.append("=============== 🔐 INSTAGRAM SECURITY REPORT ===============")
        score = self.compute_score()
        lines.append(f"\nSecurity Score: {score}/100")
        if score >= 80:
            lines.append("Overall: ✅ Good – your account is fairly well protected.")
        elif score >= 50:
            lines.append("Overall: ⚠ Medium – there is room to improve your security.")
        else:
            lines.append("Overall: 🔥 Weak – you should fix the WARN items soon.")

        levels = ["WARN", "OK", "INFO"]
        labels = {
            "WARN": "⚠ IMPORTANT ISSUES",
            "OK": "✅ Good",
            "INFO": "ℹ Info / Manual checks",
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
        lines.append("============================================================")
        return "\n".join(lines)


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
    login_btn.click()

    print("\nIf Instagram shows 2FA / ‘Save login info’ / ‘Turn on notifications’,")
    print("please handle it in the browser window.")
    time.sleep(12)
    input("➡ When you are fully logged in (see your feed/profile), press Enter here to continue... ")


def check_2fa(driver):
    """
    Roughly detect whether 2FA is enabled by inspecting the 2FA settings page.
    Instagram may change this UI anytime, so this is best-effort only.
    """
    findings = []
    print("\n[+] Checking 2FA status...")
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
    print("\n[+] Checking email & phone...")
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
    print("\n[+] Checking if account is Private or Public (best-effort)...")
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


def manual_security_recommendations():
    findings = []
    findings.append(Finding(
        "INFO",
        "Review Login Activity.",
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
    return findings


# ================== High-Level Flows (Menu Actions) ==================

def run_full_scan():
    """
    Ask for username & password, run full scan, return SecurityReport.
    """
    print("\n=== FULL INSTAGRAM SECURITY SCAN ===")
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
        report.extend(manual_security_recommendations())
    finally:
        choice = input("\nPress Enter to close browser, or type 'keep' to leave it open: ").strip()
        if choice.lower() != "keep":
            driver.quit()

    print("\nScan completed.\n")
    print(report.render())
    return report


def run_password_check_only():
    print("\n=== PASSWORD STRENGTH CHECK ===")
    password = getpass("Enter your Instagram password (or similar) to evaluate (hidden): ")

    report = SecurityReport()
    report.extend(check_password_strength(password))

    print("\nPassword check result:\n")
    print(report.render())
    return report


def show_general_tips():
    print("\n=== GENERAL INSTAGRAM SECURITY TIPS ===\n")
    tips_report = SecurityReport()
    tips_report.extend(manual_security_recommendations())
    print(tips_report.render())
    return tips_report


def export_report_to_file(report):
    if report is None or report.is_empty():
        print("\nNo report available to export. Run a scan first.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"insta_security_report_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report.render())
        f.write("\n")

    print(f"\nReport exported to: {filename}")


# ================== CLI Menu ==================

def print_menu():
    print_banner()
    print("1) Full security scan (login + settings check)")
    print("2) Password strength check only (local)")
    print("3) Show general security tips")
    print("4) Export last report to file")
    print("0) Exit")
    print("==========================================================")


def main():
    last_report = None

    while True:
        print_menu()
        choice = input("Select option: ").strip()

        if choice == "1":
            last_report = run_full_scan()
        elif choice == "2":
            last_report = run_password_check_only()
        elif choice == "3":
            last_report = show_general_tips()
        elif choice == "4":
            export_report_to_file(last_report)
        elif choice == "0":
            print("\nGoodbye. Stay safe online 🛡️")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

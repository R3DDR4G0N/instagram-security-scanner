from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from getpass import getpass
import time
import string


# ------------- CONFIG: Ubuntu + Chrome ----------------
def create_driver():
    """
    Create and return a Chrome WebDriver instance.
    Uses Selenium Manager (Selenium 4.6+) to auto-manage chromedriver.
    """
    options = webdriver.ChromeOptions()
    # Comment this line if you want to SEE the browser window:
    # options.add_argument("--headless=new")
    options.add_argument("--disable-notifications")
    options.add_argument("--start-maximized")
    return webdriver.Chrome(options=options)
# ------------------------------------------------------


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


def check_password_strength(password, findings):
    """
    Local password strength check.
    We already have the password for login.
    We never print the password itself, only its strength.
    """
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


def check_2fa(driver, findings):
    """
    Roughly detect whether 2FA is enabled by inspecting the 2FA settings page.
    Instagram may change this UI anytime, so this is best-effort only.
    """
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


def check_email_phone(driver, findings):
    """
    Check if email and phone number are set on the account
    by visiting the Edit Profile page.
    """
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


def check_privacy(driver, findings):
    """
    Best-effort check of account privacy from the Privacy & Security settings page.
    """
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


def add_manual_recommendations(findings):
    """
    Add general manual security tips to the findings list.
    """
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
        "Use strong password + 2FA on email too."
    ))


def print_report(findings):
    """
    Print final security report grouped by severity level.
    """
    print("\n================= 🔐 INSTAGRAM SECURITY REPORT =================")

    levels = ["WARN", "OK", "INFO"]
    labels = {
        "WARN": "⚠ IMPORTANT ISSUES",
        "OK": "✅ Good",
        "INFO": "ℹ Info / Manual checks",
    }

    for lvl in levels:
        subset = [f for f in findings if f.level == lvl]
        if not subset:
            continue
        print(f"\n--- {labels[lvl]} ---")
        for f in subset:
            print(str(f))

    print("\n================================================================")
    print("Note: This tool is a helper, not a perfect scanner.")
    print("Always double-check security settings manually inside Instagram.")


def main():
    print("=== Instagram Full Security Scanner ===")
    print("For YOUR OWN ACCOUNT ONLY.")
    print("Runs locally; does not send data anywhere except Instagram.\n")

    username = input("Enter your Instagram username: ").strip()
    password = getpass("Enter your Instagram password (hidden): ")

    findings = []
    check_password_strength(password, findings)

    driver = create_driver()

    try:
        login(driver, username, password)
        check_2fa(driver, findings)
        check_email_phone(driver, findings)
        check_privacy(driver, findings)
        add_manual_recommendations(findings)
        print_report(findings)
    finally:
        choice = input(
            "\nPress Enter to close browser, or type 'keep' to leave it open: "
        ).strip()
        if choice.lower() != "keep":
            driver.quit()


if __name__ == "__main__":
    main()

# Defensive-OSINT-Privacy-Audit-Framework
Defensive OSINT &amp; Privacy Audit Framework **Author: Bardiya Shokri | Security Research | 2026**
---

## Part 1: Defensive OSINT for Organizations

### 1.1 What Is Defensive OSINT?

Defensive OSINT means **attacking your own exposure before adversaries do** — systematically finding what information about your organization and employees is publicly available, then reducing that surface.

### 1.2 Organizational Exposure Vectors

| Vector | Risk Level | Example |
|--------|-----------|---------|
| Employee LinkedIn profiles | High | Job title, email pattern, phone |
| Domain WHOIS records | Medium | Registrant name, phone |
| GitHub repositories | High | API keys, internal emails |
| Job postings | Medium | Tech stack, internal tool names |
| Press releases / PDFs | Low-Medium | Employee names, direct lines |
| Google cached pages | Medium | Removed but still indexed content |

### 1.3 Audit Methodology (Red Team Mindset)

```
Phase 1: Passive Reconnaissance
  └── Google dorking against your own domain
  └── Breach database checks (HaveIBeenPwned API)
  └── Social media enumeration

Phase 2: Active Enumeration
  └── WHOIS history analysis
  └── Certificate Transparency logs (crt.sh)
  └── Wayback Machine crawl

Phase 3: Reporting & Remediation
  └── Exposure scoring per employee
  └── Prioritized remediation roadmap
  └── Re-audit schedule (quarterly)
```

---

## Part 2: Python Code — Scanning YOUR OWN Exposure

> ⚠️ These scripts are for auditing data **you own or are authorized to check**. All examples use only Python standard library — no third-party packages.

---

### 2.1 Google Dork Query Generator

این کد دورک‌های آماده برای بررسی exposure خودت می‌سازه:

```python
"""
Self-Exposure Google Dork Generator
Author: Bardiya Shokri
Purpose: Generate audit queries for your own digital footprint
"""

import urllib.parse
import webbrowser

def generate_dorks(name: str, email: str, domain: str) -> dict:
    """
    Generate Google dork queries to audit your own public exposure.
    Returns a dict of category -> list of queries.
    """
    dorks = {
        "Personal Info Exposure": [
            f'"{name}" "phone" OR "mobile" OR "tel"',
            f'"{name}" "email" site:linkedin.com OR site:github.com',
            f'"{email}" -site:{domain}',
        ],
        "Document Leakage": [
            f'"{name}" filetype:pdf OR filetype:doc OR filetype:xls',
            f'"{domain}" filetype:pdf "confidential" OR "internal"',
        ],
        "Code Repository Leakage": [
            f'"{email}" site:github.com OR site:gitlab.com',
            f'"{domain}" "api_key" OR "password" OR "secret" site:github.com',
        ],
        "WHOIS / Domain Exposure": [
            f'"{name}" site:whois.domaintools.com OR site:who.is',
        ],
        "Cached / Removed Pages": [
            f'cache:"{domain}" "{name}"',
        ],
    }
    return dorks


def encode_for_google(query: str) -> str:
    base = "https://www.google.com/search?q="
    return base + urllib.parse.quote(query)


def run_audit(name: str, email: str, domain: str):
    dorks = generate_dorks(name, email, domain)
    print(f"\n{'='*60}")
    print(f"  SELF-EXPOSURE AUDIT REPORT")
    print(f"  Target: {name} | {email} | {domain}")
    print(f"{'='*60}\n")

    for category, queries in dorks.items():
        print(f"[+] {category}")
        for q in queries:
            print(f"    Query : {q}")
            print(f"    URL   : {encode_for_google(q)}")
        print()


if __name__ == "__main__":
    # --- FILL IN YOUR OWN INFORMATION ---
    YOUR_NAME   = "Bardiya Shokri"
    YOUR_EMAIL  = "bardiya@example.com"
    YOUR_DOMAIN = "example.com"
    # ------------------------------------
    run_audit(YOUR_NAME, YOUR_EMAIL, YOUR_DOMAIN)
```

---

### 2.2 Email Breach Checker (HaveIBeenPwned API)

```python
"""
Breach Exposure Checker — HaveIBeenPwned v3 API
Purpose: Check if YOUR email appears in known data breaches
Requires: Free HIBP API key from haveibeenpwned.com
"""

import urllib.request
import urllib.error
import json
import time

HIBP_API_KEY = "YOUR_API_KEY_HERE"   # Get free key at haveibeenpwned.com

def check_email_breaches(email: str) -> list:
    """Check a single email against HIBP breach database."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
    
    req = urllib.request.Request(url)
    req.add_header("hibp-api-key", HIBP_API_KEY)
    req.add_header("user-agent", "SelfAuditTool/1.0")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []   # Not found in any breach — good!
        elif e.code == 401:
            print("[-] Invalid API key.")
        elif e.code == 429:
            print("[-] Rate limited. Wait 1 minute.")
        return []


def audit_emails(email_list: list):
    print(f"\n{'='*55}")
    print("  EMAIL BREACH AUDIT")
    print(f"{'='*55}")

    for email in email_list:
        print(f"\n[?] Checking: {email}")
        breaches = check_email_breaches(email)
        
        if not breaches:
            print("  [✓] Not found in any known breach.")
        else:
            print(f"  [!] Found in {len(breaches)} breach(es):")
            for b in breaches:
                print(f"      - {b.get('Name')} ({b.get('BreachDate')})")
                print(f"        Data: {', '.join(b.get('DataClasses', []))}")
        
        time.sleep(1.5)   # Respect API rate limits


if __name__ == "__main__":
    # --- YOUR EMAILS TO AUDIT ---
    MY_EMAILS = [
        "bardiya@example.com",
        "bardiya.work@company.com",
    ]
    # ----------------------------
    audit_emails(MY_EMAILS)
```

---

### 2.3 Certificate Transparency Log Scanner

```python
"""
Certificate Transparency Scanner
Purpose: Find all subdomains of YOUR domain exposed via CT logs
Source: crt.sh (public, no auth required)
"""

import urllib.request
import json

def scan_ct_logs(domain: str) -> list:
    """Query crt.sh for all certificates issued for your domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "DefensiveAuditTool/1.0")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        subdomains.add(sub)
            return sorted(subdomains)
    except Exception as e:
        print(f"[-] Error: {e}")
        return []


def run_ct_audit(domain: str):
    print(f"\n[CT LOG SCAN] Domain: {domain}")
    print("-" * 45)
    subdomains = scan_ct_logs(domain)
    
    if not subdomains:
        print("  No subdomains found.")
        return

    print(f"  Found {len(subdomains)} exposed subdomains:\n")
    for sub in subdomains:
        print(f"    • {sub}")
    
    print(f"\n[!] Review each subdomain for unintended exposure.")


if __name__ == "__main__":
    YOUR_DOMAIN = "example.com"
    run_ct_audit(YOUR_DOMAIN)
```

---

## Part 3: Data Broker Opt-Out Automation

### 3.1 Major Data Brokers & Their Opt-Out URLs

```python
"""
Data Broker Opt-Out Directory
Purpose: Systematic removal of YOUR data from broker sites
"""

DATA_BROKERS = [
    {
        "name": "Spokeo",
        "opt_out_url": "https://www.spokeo.com/optout",
        "method": "Web form",
        "time_to_remove": "3-7 days",
        "requires": ["Full name", "City/State", "Email for confirmation"],
    },
    {
        "name": "Whitepages",
        "opt_out_url": "https://www.whitepages.com/suppression_requests",
        "method": "Web form + phone verification",
        "time_to_remove": "1-3 days",
        "requires": ["Full name", "Address", "Phone number to verify"],
    },
    {
        "name": "BeenVerified",
        "opt_out_url": "https://www.beenverified.com/app/optout/search",
        "method": "Web form",
        "time_to_remove": "5-10 days",
        "requires": ["Full name", "State", "Email"],
    },
    {
        "name": "Intelius",
        "opt_out_url": "https://www.intelius.com/opt-out",
        "method": "Web form",
        "time_to_remove": "7 days",
        "requires": ["Full name", "City", "State"],
    },
    {
        "name": "PeopleFinder",
        "opt_out_url": "https://www.peoplefinders.com/opt-out",
        "method": "Web form + CAPTCHA",
        "time_to_remove": "5-7 days",
        "requires": ["Full name", "State"],
    },
    {
        "name": "Radaris",
        "opt_out_url": "https://radaris.com/page/how-to-remove",
        "method": "Email request",
        "time_to_remove": "7-14 days",
        "requires": ["Profile URL", "Email to privacy@radaris.com"],
    },
    {
        "name": "ZabaSearch",
        "opt_out_url": "https://www.zabasearch.com/block_records/",
        "method": "Web form",
        "time_to_remove": "3-5 days",
        "requires": ["Full name", "City", "State"],
    },
    {
        "name": "MyLife",
        "opt_out_url": "https://www.mylife.com/privacy/remove-my-information.pubview",
        "method": "Phone call required: 1-888-704-1900",
        "time_to_remove": "1-2 days",
        "requires": ["Phone call + account ID"],
    },
]


def print_optout_checklist(your_name: str):
    print(f"\n{'='*60}")
    print(f"  DATA BROKER OPT-OUT CHECKLIST")
    print(f"  Subject: {your_name}")
    print(f"{'='*60}\n")

    for i, broker in enumerate(DATA_BROKERS, 1):
        print(f"[{i:02d}] {broker['name']}")
        print(f"     URL     : {broker['opt_out_url']}")
        print(f"     Method  : {broker['method']}")
        print(f"     Removal : {broker['time_to_remove']}")
        print(f"     You need: {', '.join(broker['requires'])}")
        print(f"     Status  : [ ] Pending")
        print()

    print(f"Total brokers to opt out from: {len(DATA_BROKERS)}")
    print("Recommendation: Re-audit after 90 days (brokers re-add data).")


if __name__ == "__main__":
    print_optout_checklist("Bardiya Shokri")
```

---

### 3.2 Opt-Out Email Generator

```python
"""
GDPR / CCPA Opt-Out Email Generator
Purpose: Auto-generate formal removal request emails
"""

from datetime import date

def generate_removal_email(
    your_name: str,
    your_email: str,
    broker_name: str,
    profile_url: str = None
) -> str:
    
    today = date.today().strftime("%B %d, %Y")
    profile_line = f"\nProfile URL: {profile_url}" if profile_url else ""

    email = f"""
Subject: Data Removal Request — {your_name} — GDPR/CCPA

Date: {today}
To: Privacy Team, {broker_name}
From: {your_email}

Dear Privacy/Compliance Team,

I am formally requesting the deletion and suppression of all personal 
data associated with me from your platform and any downstream partners 
you share data with.

Subject of Request:
  Full Name : {your_name}
  Email     : {your_email}{profile_line}

Legal Basis:
  • CCPA (California Consumer Privacy Act) — Right to Delete (§1798.105)
  • GDPR Article 17 — Right to Erasure
  • PIPEDA (if applicable)

I request that you:
  1. Delete all records containing my personal information
  2. Suppress future re-addition of my data
  3. Confirm deletion in writing within 30 days

Failure to comply may result in a complaint to the relevant supervisory 
authority (FTC, ICO, or equivalent).

Sincerely,
{your_name}
{your_email}
{today}
"""
    return email.strip()


if __name__ == "__main__":
    brokers_needing_email = ["Radaris", "Acxiom", "LexisNexis"]
    
    for broker in brokers_needing_email:
        print("\n" + "="*60)
        email_text = generate_removal_email(
            your_name    = "Bardiya Shokri",
            your_email   = "bardiya@example.com",
            broker_name  = broker,
            profile_url  = f"https://www.{broker.lower()}.com/profile/example"
        )
        print(email_text)
```

---

## Part 4: Privacy Monitoring Tools

### 4.1 Personal Exposure Score Calculator

```python
"""
Privacy Exposure Scoring System
Purpose: Quantify your current digital privacy risk
"""

EXPOSURE_CHECKS = {
    "Social Media": {
        "phone_on_facebook"        : (15, "Remove phone from Facebook profile"),
        "phone_on_instagram"       : (10, "Set Instagram to private"),
        "phone_on_linkedin"        : (20, "Hide phone from LinkedIn"),
        "real_name_on_twitter"     : (5,  "Consider a pseudonym"),
    },
    "Domain & Web": {
        "whois_not_private"        : (20, "Enable WHOIS privacy on registrar"),
        "indexed_in_data_broker"   : (25, "Submit opt-out requests"),
        "old_forum_posts_with_info": (10, "Request deletion from forum admins"),
    },
    "Email & Accounts": {
        "email_in_breach"          : (30, "Change password + enable 2FA"),
        "same_email_everywhere"    : (15, "Use email aliases (SimpleLogin/AnonAddy)"),
        "email_publicly_listed"    : (10, "Remove from public directories"),
    },
    "Phone Number": {
        "real_number_used_publicly": (25, "Switch to virtual number (Google Voice)"),
        "number_in_breach_data"    : (30, "Contact carrier for new number"),
        "number_on_job_sites"      : (15, "Remove from public job profiles"),
    },
}

def calculate_exposure_score(answers: dict) -> None:
    """
    answers: dict of check_key -> True (exposed) / False (safe)
    """
    total_risk = 0
    max_risk = 0
    findings = []

    for category, checks in EXPOSURE_CHECKS.items():
        for check_key, (score, recommendation) in checks.items():
            max_risk += score
            if answers.get(check_key, False):
                total_risk += score
                findings.append((score, category, check_key, recommendation))

    # Sort by severity
    findings.sort(reverse=True)

    percentage = (total_risk / max_risk) * 100
    
    if percentage >= 70:
        risk_level = "CRITICAL"
    elif percentage >= 40:
        risk_level = "HIGH"
    elif percentage >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    print(f"\n{'='*55}")
    print(f"  PRIVACY EXPOSURE SCORE")
    print(f"{'='*55}")
    print(f"  Score     : {total_risk} / {max_risk} points")
    print(f"  Risk Level: {risk_level} ({percentage:.1f}%)")
    print(f"\n  Top Remediation Actions:")
    
    for i, (score, cat, key, rec) in enumerate(findings[:5], 1):
        print(f"  {i}. [{score:2d} pts] {cat}: {rec}")


if __name__ == "__main__":
    # Set True for each item that applies to you
    my_exposure = {
        "phone_on_linkedin"        : True,
        "whois_not_private"        : True,
        "indexed_in_data_broker"   : True,
        "email_in_breach"          : True,
        "real_number_used_publicly": True,
        "same_email_everywhere"    : False,
        "phone_on_facebook"        : False,
        "number_in_breach_data"    : False,
    }
    calculate_exposure_score(my_exposure)
```

---

## Part 5: Summary — Defense-in-Depth Model

```
LAYER 1 — Prevention
  ├── Virtual phone number for all public registrations
  ├── Email aliases (not your real address)
  └── WHOIS privacy on all domains

LAYER 2 — Reduction
  ├── Quarterly data broker opt-out campaign
  ├── Minimal social media info (no phone, no address)
  └── Separate work / personal / burner identities

LAYER 3 — Detection
  ├── Google Alerts on your name + "phone" OR "email"
  ├── HIBP monitoring for breach alerts
  └── CT log monitoring for rogue subdomains

LAYER 4 — Response
  ├── GDPR/CCPA formal removal emails (see Part 3.2)
  ├── Legal escalation if removals are ignored
  └── Phone number change if compromised in breach
```

---

*Author: Bardiya Shokri | Defensive Security Research | 2026*
*All code examples use Python standard library only. No third-party dependencies required.*

"""
SOC Mail Analysis Tool — Central Configuration
================================================
All configurable parameters, API keys, thresholds, and constants.
API keys default to environment variables for security.
"""
import os

# ─── API Keys (use env vars in production) ──────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOURS")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOURS")

# ─── VirusTotal Endpoints ───────────────────────────────────────────────
VIRUSTOTAL_URL_REPORT_ENDPOINT = "https://www.virustotal.com/vtapi/v2/url/report"
VIRUSTOTAL_FILE_REPORT_ENDPOINT = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_DOMAIN_REPORT_ENDPOINT = "https://www.virustotal.com/vtapi/v2/domain/report"
VIRUSTOTAL_IP_REPORT_ENDPOINT = "https://www.virustotal.com/vtapi/v2/ip-address/report"
VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute (free tier)

# ─── AbuseIPDB Endpoints ────────────────────────────────────────────────
ABUSEIPDB_CHECK_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

# ─── Thresholds ─────────────────────────────────────────────────────────
URL_SCAN_THRESHOLD = 3          # VT positives to flag URL as dangerous
ATTACHMENT_SCAN_THRESHOLD = 3   # VT positives to flag attachment
MAX_ATTACHMENT_SIZE = 32 * 1024 * 1024  # 32 MB
DOMAIN_AGE_THRESHOLD_DAYS = 30  # Domains younger than this are suspicious
ABUSEIPDB_CONFIDENCE_THRESHOLD = 50  # AbuseIPDB score to flag IP

# ─── Verdict Thresholds ─────────────────────────────────────────────────
VERDICT_LEGITIMATE_MAX = 25
VERDICT_SUSPICIOUS_MAX = 45
VERDICT_LIKELY_PHISHING_MAX = 70
# Anything above 70 is CONFIRMED SPOOFED/MALICIOUS

# ─── Risk Scoring Weights ───────────────────────────────────────────────
WEIGHT_AUTH = 30        # SPF/DKIM/DMARC/ARC
WEIGHT_DOMAIN = 20     # Domain intelligence
WEIGHT_HEADER = 20     # Header forensics
WEIGHT_REPUTATION = 15 # Sender reputation
WEIGHT_BODY = 15       # Body/content analysis

# ─── Suspicious Extensions ──────────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.mst',
    '.cpl', '.hta', '.inf', '.ins', '.isp', '.reg', '.rgs', '.sct',
    '.shb', '.shs', '.ws', '.xnk', '.dll', '.sys', '.drv',
    '.iso', '.img', '.vhd', '.vhdx',  # Disk images (bypass Mark of Web)
    '.lnk', '.url',                     # Shortcut files
    '.docm', '.xlsm', '.pptm',          # Macro-enabled Office
    '.jar', '.class',                    # Java
    '.html', '.htm',                      # HTML smuggling (exclude .svg — too common)
]

# ─── Known Free Email Providers ─────────────────────────────────────────
FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
    'gmx.com', 'gmx.net', 'live.com', 'msn.com', 'inbox.com',
    'fastmail.com', 'tutanota.com', 'mail.ru', 'rambler.ru',
]

# ─── Known Spamming Tools (X-Mailer patterns) ───────────────────────────
SUSPICIOUS_MAILERS = [
    'phpmailer', 'swiftmailer', 'king mailer', 'leaf mailer',
    'atompark', 'sendy', 'mailwizz', 'interspire', 'gammadyne',
    'turbo mailer', 'group mail', 'sendblaster', 'advanced mass sender',
    'mail merge toolkit', 'emailsmartz',
]

# ─── Known Good Relay Domains ───────────────────────────────────────────
TRUSTED_RELAY_DOMAINS = [
    'google.com', 'googlemail.com', 'outlook.com', 'microsoft.com',
    'office365.com', 'protection.outlook.com', 'amazonses.com',
    'sendgrid.net', 'mailgun.org', 'mandrill.com', 'sparkpostmail.com',
    'mimecast.com', 'proofpoint.com', 'barracuda.com',
]

# ─── DNS Blocklists for IP Reputation ───────────────────────────────────
DNS_BLOCKLISTS = [
    'zen.spamhaus.org',
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'cbl.abuseat.org',
    'dnsbl-1.uceprotect.net',
]

# ─── URL Shortener Domains ──────────────────────────────────────────────
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'short.link', 'cutt.ly', 'rb.gy',
    'tiny.cc', 'lnkd.in', 'surl.li', 'shorturl.at',
]

# ─── Phishing Keywords (case-insensitive) ───────────────────────────────
# NOTE: Only include phrases with high phishing specificity.
# Avoid common legitimate phrases like "expire", "security alert",
# "reset your password", "billing information", "dear customer" — these
# trigger false positives on legitimate transactional/notification emails.
PHISHING_KEYWORDS = [
    'verify your account', 'confirm your identity',
    'unusual activity', 'unauthorized access', 'click here immediately',
    'urgent action required', 'your account will be',
    'act now', 'verify your information',
    'confirm ownership', 'account has been compromised', 'validate your',
    'dear valued',
]

# ─── Strong Phishing Phrases (require fewer matches to flag) ────────────
# These are almost never found in legitimate emails.
STRONG_PHISHING_KEYWORDS = [
    'click here immediately', 'account has been compromised',
    'unauthorized access detected', 'verify your identity within',
    'your account will be permanently', 'act now or',
    'validate your credentials',
]

# ─── Phishing Keyword Thresholds ────────────────────────────────────────
PHISHING_KEYWORDS_LOW_THRESHOLD = 2   # ≥2 generic keywords → LOW
PHISHING_KEYWORDS_HIGH_THRESHOLD = 4  # ≥4 generic keywords → HIGH
STRONG_PHISHING_THRESHOLD = 1         # ≥1 strong keyword → HIGH

# ─── Logging ─────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# ─── Report Output ──────────────────────────────────────────────────────
REPORT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

"""Generate a large, diverse synthetic dataset for PhishGuard v4 training.

Target: ~20,400 balanced samples
  URL:   3,400 phishing + 3,400 safe
  Email: 3,000 phishing + 3,000 safe
  SMS:   1,000 phishing + 1,000 safe

Design goals:
- Wide vocabulary variation so models learn signals not surface patterns.
- Edge cases: safe messages with some urgency language, phishing with HTTPS,
  borderline delivery notifications, terse professional emails.
- New features (uppercase_ratio, keyword_density, domain_entropy, etc.)
  are exercised by the generated content.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

random.seed(42)

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "data" / "phishing_dataset.csv"

# ---------------------------------------------------------------------------
# Shared brand / domain pools
# ---------------------------------------------------------------------------

BRANDS = [
    ("PayPal",       "paypal.com"),
    ("Amazon",       "amazon.com"),
    ("Microsoft",    "microsoft.com"),
    ("Apple",        "apple.com"),
    ("Netflix",      "netflix.com"),
    ("Google",       "google.com"),
    ("Chase Bank",   "chase.com"),
    ("Wells Fargo",  "wellsfargo.com"),
    ("DHL",          "dhl.com"),
    ("LinkedIn",     "linkedin.com"),
    ("Instagram",    "instagram.com"),
    ("Facebook",     "facebook.com"),
    ("Coinbase",     "coinbase.com"),
    ("Binance",      "binance.com"),
    ("USPS",         "usps.com"),
    ("FedEx",        "fedex.com"),
    ("UPS",          "ups.com"),
    ("Uber",         "uber.com"),
    ("Airbnb",       "airbnb.com"),
    ("Dropbox",      "dropbox.com"),
    ("Spotify",      "spotify.com"),
    ("Twitter",      "twitter.com"),
    ("WhatsApp",     "whatsapp.com"),
    ("Venmo",        "venmo.com"),
    ("Stripe",       "stripe.com"),
    ("Slack",        "slack.com"),
    ("Zoom",         "zoom.us"),
    ("Adobe",        "adobe.com"),
    ("Shopify",      "shopify.com"),
    ("eBay",         "ebay.com"),
]

SAFE_NAMES = [
    "Alex","Riley","Taylor","Jordan","Priya","Sam","Chris","Emma","Liam","Noah",
    "Olivia","Sophia","Jackson","Aria","Mateo","Wei","Fatima","Diego","Aisha",
    "Lucas","Mei","Ethan","Zara","Omar","Elena","Marcus","Yuki","Chloe","Rafael",
    "Amara","James","Sofia","Ahmed","Isabella","Daniel","Mia","Gabriel","Layla",
    "Sebastian","Nadia","Victor","Hana","Patrick","Leila","Sean","Carmen","Raj",
]

FREE_MAIL = [
    "gmail.com","yahoo.com","outlook.com","hotmail.com",
    "icloud.com","protonmail.com","me.com","live.com",
]

# ---------------------------------------------------------------------------
# Phishing URL building blocks
# ---------------------------------------------------------------------------

SUSPICIOUS_DOMAINS = [
    "secure-paypal-login.com","verify-microsoft-account.co","netflix-billing-update.com",
    "banking-secure-check.com","appleid-confirm-support.com","amazon-update-alert.net",
    "google-security-verify.com","chase-login-portal.net","login-secure-auth.org",
    "verify-identity-alert.net","delivery-pending-fee.com","usps-package-fee.info",
    "wellsfargo-secure-verify.com","dhl-tracking-update.net","linkedin-account-check.co",
    "facebook-security-login.com","instagram-verify-account.net","coinbase-wallet-secure.com",
    "binance-account-verify.net","fedex-delivery-confirm.com","ups-track-update.net",
    "apple-id-verify-now.com","microsoft-support-alert.com","amazon-order-verify.net",
    "paypal-resolution-center.com","netflix-payment-confirm.com","account-verify-secure.net",
    "secure-account-alert.com","login-verify-portal.net","billing-confirm-update.co",
    "auth-identity-check.com","service-account-secure.net","update-billing-alert.com",
    "verify-account-now.net","secure-login-confirm.org","identity-verify-portal.com",
    "customer-verify-secure.net","account-support-verify.com","signin-confirm-secure.net",
    "validate-account-portal.com","access-verify-secure.co","my-account-verify.net",
    "account-locked-verify.com","security-check-portal.net","unlock-account-secure.com",
]

TYPOSQUAT_DOMAINS = [
    "paypa1.com","paypol.com","pay-pal.com","paypa1.net","paypall.com",
    "arnazon.com","amaz0n.com","amazon-secure.com","amazoon.com","arnazon.net",
    "micros0ft.com","microsoft-login.net","microsofft.com","microsooft.com",
    "app1e.com","apple-id.support","appleid-verify.net","aple.com","appie.com",
    "netf1ix.com","netfilx.com","netflix-account.net","netfix.com","netlfix.com",
    "go0gle.com","googie.com","gooogle.com","googgle.com","g00gle.com",
    "faceb00k.com","faecbook.com","facebook-verify.net","facebok.com","facbook.com",
    "lnstagram.com","instagran.com","instagrarn.com","lnstgram.com",
    "coinbose.com","c0inbase.com","coinbase-support.net","co1nbase.com",
    "paypall.net","linkedln.com","lnkedin.com","linkediin.com",
    "drropbox.com","dropb0x.com","sp0tify.com","spotlfy.com",
    "ub3r.com","ubber.com","uberr.com","twltter.com","tw1tter.com",
]

ATTACKER_DOMAINS = [
    "evil-corp.com","phish-site.net","malware-host.com","attacker.io",
    "badguy.xyz","hacker-group.net","phishing.club","scam.top",
    "fake-alert.com","identity-steal.net","data-harvest.xyz","cred-grab.top",
    "account-stealer.net","login-capture.com","auth-phish.xyz","user-data.top",
    "secure-capture.net","info-steal.club","verify-phish.online","alert-scam.site",
]

SUBDOMAIN_BRAND_PREFIXES = [
    "paypal","amazon","microsoft","apple","netflix","google",
    "secure","login","account","verify","billing","auth","support",
]

SHORTENERS = [
    "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly",
    "is.gd","buff.ly","rebrand.ly","cutt.ly","short.io",
    "rb.gy","tiny.cc","shorturl.at","bl.ink",
]

IP_ADDRESSES = [
    "192.168.0.1","10.0.0.1","172.16.254.1","167.119.148.251","139.113.22.187",
    "35.0.109.123","215.76.242.207","192.30.117.18","127.55.62.65",
    "94.130.22.45","185.220.101.1","45.33.32.156","198.51.100.42","203.0.113.77",
    "91.108.4.200","176.9.0.207","159.65.12.34","104.21.55.201","172.67.143.82",
    "23.95.201.45","31.13.72.36","78.46.91.212","162.243.168.211","130.211.55.20",
]

SUSPICIOUS_TLDS_LIST = [
    ".xyz",".top",".club",".info",".tk",".ml",".ga",
    ".cf",".gq",".pw",".work",".online",".site",".space",
    ".buzz",".click",".link",".live",".win",".icu",".vip",
]

PHISHING_PATHS = [
    "/login/verify","/account/confirm","/security/update","/billing/check",
    "/verify/identity","/confirm/account","/secure/login","/auth/validate",
    "/reset/password","/account/suspended","/verify/email","/confirm/payment",
    "/update/credentials","/signin/confirm","/recover/account",
    "/wallet/verify","/payment/update","/account/unlock","/reactivate/now",
    "/secure/confirm","/verify/otp","/confirm/identity","/account/restore",
    "/auth/confirm","/login/confirm","/secure/update","/validate/account",
]

OBFUSCATED_PATHS = [
    "/login%20verify/confirm","/account%2Fverify?redirect=@evil.com",
    "/secure/../login/./verify","/auth/confirm?ref=0x4d61696c",
    "/.well-known/verify/account","/wp-admin/login.php",
    "/xmlrpc.php?rpc_call=verify","/admin/index.php?action=verify",
    "/cgi-bin/verify.pl?action=login","/include/redirect.php?url=steal",
    "/login?next=%2Faccount%2Fverify","/auth?token=aGFja2Vy&redirect=@phish",
]

# ---------------------------------------------------------------------------
# Safe URL building blocks
# ---------------------------------------------------------------------------

SAFE_BRANDS_URLS = [
    ("GitHub",          "github.com"),
    ("Stack Overflow",  "stackoverflow.com"),
    ("Wikipedia",       "wikipedia.org"),
    ("BBC",             "bbc.com"),
    ("NYT",             "nytimes.com"),
    ("MDN",             "developer.mozilla.org"),
    ("Python Docs",     "docs.python.org"),
    ("AWS Docs",        "docs.aws.amazon.com"),
    ("Azure",           "azure.microsoft.com"),
    ("Hacker News",     "news.ycombinator.com"),
    ("Reddit",          "reddit.com"),
    ("Medium",          "medium.com"),
    ("Dev.to",          "dev.to"),
    ("Khan Academy",    "khanacademy.org"),
    ("Coursera",        "coursera.org"),
]

SAFE_PATHS = [
    "support","help","orders","dashboard","billing/history",
    "account/notifications","settings","products","faq","contact",
    "about","careers","blog","news","docs","api","changelog",
    "legal/privacy","legal/terms","security","status","pricing",
    "download","releases","wiki","community","forum","guides",
    "profile","preferences","notifications","invoices","receipts",
    # Paths that look like phishing paths but belong to legit domains
    "account/security","account/billing","account/payments",
    "account/login","account/signin","billing/update",
    "security/settings","security/devices","payments/history",
    "login","signin","verify-email","confirm-email",
    "reset-password","account/verify","account/confirm",
]

# Borderline safe email bodies — legitimate messages with urgency-adjacent
# language that should still score Safe or at most low Suspicious.
SAFE_BORDERLINE_BODIES = [
    "Hi {name}, we noticed a login to your {brand} account from a new location. If this was you, no action is needed. If not, secure your account at https://www.{domain}/security.",
    "Hi {name}, your {brand} payment of ${amount} failed. Please update your payment method at https://www.{domain}/billing to keep your subscription active.",
    "Hi {name}, your {brand} account has been inactive for 90 days. Log in at https://www.{domain}/account to keep it active, or it will be archived after 30 days.",
    "Hi {name}, action needed: please verify your email address to continue using {brand}. Click the link in this email or visit https://www.{domain}/verify-email.",
    "Hi {name}, your {brand} subscription is expiring soon. Renew at https://www.{domain}/billing to avoid any interruption to your service.",
    "Hi {name}, we are updating our security policies on {date}. Review what's changing at https://www.{domain}/security.",
    "Hi {name}, your {brand} account password will expire in 14 days. You can reset it at https://www.{domain}/reset-password at any time.",
    "Hi {name}, we could not process your {brand} payment of ${amount}. Please review your billing details at https://www.{domain}/billing.",
    "Hi {name}, your {brand} account email was recently changed. If you made this change, no action needed. If not, contact us immediately.",
    "Hi {name}, this is your final reminder to complete your {brand} profile setup before {date}.",
]

SAFE_SUBDOMAINS = [
    "www","docs","help","support","blog","status","api",
    "developer","mail","accounts","cdn","static","media",
]

# ---------------------------------------------------------------------------
# Text content pools — phishing
# ---------------------------------------------------------------------------

PHISHING_GREETINGS = [
    "Dear Customer","Dear User","Dear Valued Member","Dear Account Holder",
    "Hello User","Valued Customer","Dear member","Attention","Dear Sir/Madam",
    "Dear Account Owner","Dear Subscriber","Dear Client","Hello there",
    "Dear Policyholder","To whom it may concern","Dear Sir","Dear Madam",
    "ATTENTION","IMPORTANT NOTICE","URGENT",
]

PHISHING_URGENCY_DIRECT = [
    "act now", "verify immediately", "your account will be suspended",
    "urgent action required", "click immediately", "your account has been locked",
    "final notice", "action required", "unusual activity detected",
    "unauthorized login attempt", "security alert", "account restricted",
    "temporarily locked", "billing update required", "payment declined",
    "action needed", "immediate attention required", "suspension warning",
    "update your details now", "verify your identity immediately",
    "delivery fee pending", "package pending review", "last chance",
    "expires today", "your account will be closed in 24 hours",
    "reactivate your account now", "we detected suspicious activity",
    "access has been blocked", "confirm now or lose access",
    "respond within 24 hours", "URGENT: account compromised",
    "ALERT: unusual transaction detected", "WARNING: account at risk",
]

PHISHING_URGENCY_SUBTLE = [
    "we noticed something different about your recent sign-in",
    "there seems to be a problem with your last payment",
    "your subscription details need a quick review",
    "we could not confirm your recent transaction",
    "a step is missing before your order can ship",
    "our system flagged your account for a routine security check",
    "your profile requires re-verification before next use",
    "an unrecognized device recently accessed your account",
    "we need to confirm a few account details before continuing",
    "your account settings were recently changed — please verify",
    "we are having trouble processing your recent request",
    "your recent activity looks unusual — a quick check is needed",
    "please review your recent account changes",
    "we could not validate your payment method on file",
    "a hold has been placed on your account pending verification",
]

PHISHING_SENSITIVE = [
    "confirm your password","provide your OTP","enter your one-time code",
    "verify your card number","input your CVV","confirm your SSN",
    "confirm your PIN","provide your social security number",
    "update your billing address","provide your credit card details",
    "confirm your bank details","click the verification link",
    "confirm your security code","enter your login credentials",
    "provide your account number","enter your date of birth",
    "provide your mother's maiden name","confirm your secret answer",
    "enter your passphrase","provide your two-factor code",
    "share your authenticator code","update your payment information",
    "confirm your routing number","re-enter your password",
    "validate your identity","submit your personal details",
]

PHISHING_CLOSINGS = [
    "Failure to act will result in permanent account closure.",
    "Your access will be revoked within 24 hours.",
    "This is your final warning before suspension.",
    "Do not ignore this message.",
    "Immediate action is required to protect your account.",
    "Click below before your session expires.",
    "Your account will be permanently deleted if not verified.",
    "Respond within 12 hours to avoid service interruption.",
    "We cannot guarantee account security without your verification.",
    "",  # sometimes no closing
    "",
    "",
]

# ---------------------------------------------------------------------------
# Text content pools — safe
# ---------------------------------------------------------------------------

SAFE_GREETINGS = [
    "Hi {name}","Hello {name}","Dear {name}","Hey {name}",
    "Hi there","Hello","Good morning {name}","Hi {name}, hope you're well",
]

SAFE_EMAIL_BODIES = [
    # Transactional — contain account/payment/billing/security naturally
    "You can review your support ticket at https://www.{domain}/support. No password or payment details are required.",
    "Your monthly statement is ready. Visit your dashboard at https://www.{domain}/billing to view it.",
    "Thanks for your purchase! Your receipt is attached. No further action is needed.",
    "Please find the meeting agenda attached. Looking forward to connecting.",
    "Your subscription has been renewed successfully. Contact support if you have questions.",
    "Here is the code review document we discussed. Let me know your thoughts.",
    "We have updated our terms of service. You can read the changes at https://www.{domain}/legal.",
    "Your order #{tracking} has been shipped. Expected delivery is in 3–5 business days.",
    "Your account summary for this month is ready at https://www.{domain}/account.",
    "The weekly team report is attached. No action needed — this is for your records.",
    "Your password was successfully changed. If this was not you, contact support immediately.",
    "Your invoice is ready to view at https://www.{domain}/invoices. Payment is due in 30 days.",
    "Thanks for joining! Your account is now active. Get started at https://www.{domain}/dashboard.",
    "We have processed your refund of ${amount}. It should appear in 3–5 business days.",
    "Your free trial ends on {date}. Log in at https://www.{domain}/billing to choose a plan.",
    "Your appointment is confirmed for {date}. Add it to your calendar using the link below.",
    "We noticed you haven't logged in recently. Your data is safe — no action needed.",
    "Your export is ready to download at https://www.{domain}/exports.",
    "The project milestone has been updated. Check the timeline at https://www.{domain}/projects.",
    "Your feedback has been received. Thank you for helping us improve.",
    # Security-related but legitimate
    "Your {brand} account security settings were updated. If you did not make this change, please contact support at https://www.{domain}/support.",
    "We detected a login to your account from a new browser. If this was you, no action is needed. If not, you can review activity at https://www.{domain}/security.",
    "Two-factor authentication has been enabled on your account. You can manage security settings at https://www.{domain}/settings.",
    "Your recent payment of ${amount} to {brand} was processed successfully. View your payment history at https://www.{domain}/billing.",
    "Your billing address has been updated. If you did not make this change, contact us at https://www.{domain}/support.",
    "A new device was added to your account. Review connected devices at https://www.{domain}/security.",
    # Subscription / billing — legitimate
    "Your {brand} plan renews on {date} for ${amount}. To change or cancel, visit https://www.{domain}/billing.",
    "Your payment method ending in 4242 has been updated. No further action is required.",
    "Receipt for your {brand} subscription: ${amount} charged on {date}. View your invoices at https://www.{domain}/invoices.",
    "Your {brand} account has been upgraded. Your new plan is active immediately.",
    "We were unable to process your payment for {brand}. Please update your billing details at https://www.{domain}/billing to avoid interruption.",
    # Account / profile — legitimate
    "Your profile has been updated. View your account at https://www.{domain}/profile.",
    "You have new notifications in your {brand} account. Log in at https://www.{domain}/notifications to view them.",
    "Your API key has been rotated. Update your integration with the new key from https://www.{domain}/api.",
    "Your data export from {brand} is ready. Download it at https://www.{domain}/exports before {date}.",
    # Order / delivery — legitimate
    "Your {brand} order #{tracking} is out for delivery today. Track it at https://www.{domain}/orders.",
    "Your return for order #{tracking} has been received. Your refund of ${amount} will appear in 5–7 days.",
    "Your {brand} order has been confirmed. You will receive a shipping notification when it dispatches.",
    # Neutral professional
    "I wanted to follow up on our discussion from last week. Let me know if you have any questions.",
    "The quarterly business review is scheduled for {date}. Please review the attached deck beforehand.",
    "As discussed, I'm sharing the updated project requirements document. Let me know if you have any questions.",
    "Please find the signed contract attached. Let us know if you need any changes.",
    "Your interview is confirmed for {date}. Please bring a copy of your resume.",
]

SAFE_URGENT_BODIES = [
    "Final notice: your conference badge must be picked up by 5 PM today at the front desk.",
    "Action needed: please sign the consent form before Friday's appointment.",
    "Reminder — your loyalty points expire this weekend. Use them at https://www.{domain}/rewards.",
    "Your library book is due tomorrow. Renew online to avoid a late fee.",
    "Quick heads up: flight gate changed — boarding starts soon at gate C12.",
    "Your prescription refill is ready for pickup and will be held for 72 hours.",
    "Last call: the team lunch reservation is today at noon — please confirm attendance.",
    "The beta access period ends this Friday. Export your data before then if needed.",
    "Reminder: the deadline for expense submissions is end of business tomorrow.",
    "Your gym membership renews next week. Update payment info at https://www.{domain}/billing if needed to avoid interruption.",
    "Your {brand} account password will expire in 7 days. Reset it at https://www.{domain}/security at your convenience.",
    "Action required: your pending document must be signed by {date} to proceed.",
    "Heads up: we will be performing scheduled maintenance on {date} from 2–4 AM UTC. No action needed.",
    "Your storage is almost full. Free up space or upgrade at https://www.{domain}/settings.",
    "Reminder: your annual subscription renews on {date}. No action needed unless you wish to cancel.",
]

SAFE_NEWSLETTER_BODIES = [
    "Here's your weekly roundup of the top stories in tech, design, and culture.",
    "This month we're featuring new product updates, community highlights, and upcoming events.",
    "Check out our latest blog post on improving team productivity at https://www.{domain}/blog.",
    "We have exciting new features to share — see what's new in this release.",
    "Meet the team behind our new accessibility improvements.",
    "Our annual user survey is open. Share your feedback and help shape the product.",
    "Top picks this week: articles, tools, and resources our team loved.",
    "Behind the scenes: how we built our new infrastructure.",
    "Your monthly digest from {brand}: highlights, tips, and what's coming next.",
    "We recently published a guide on account security best practices. Read it at https://www.{domain}/blog.",
]

SAFE_CLOSING_VARIANTS = [
    "Best regards,\nThe {brand} Team.",
    "Warm regards,\n{brand} Support.",
    "Thanks,\n{brand}",
    "Sincerely,\nThe {brand} Team.",
    "Cheers,\n{brand}",
    "Take care,\n{brand} Team",
    "",
]

# ---------------------------------------------------------------------------
# SMS pools
# ---------------------------------------------------------------------------

SMS_PHISHING_TEMPLATES = [
    # Delivery
    "Your {brand} package #{tracking} requires a delivery fee of ${amount}. Pay now: {url}",
    "{brand} delivery attempt failed. Reschedule and pay ${amount} fee: {url}",
    "Your parcel is on hold due to unpaid customs fee. Complete now: {url}",
    "USPS: Package undeliverable. Update delivery address to release: {url}",
    "{brand}: Action required to release your shipment. Confirm here: {url}",
    "Your {brand} delivery is pending. A small fee of ${amount} is required: {url}",
    "ALERT: {brand} package #{tracking} held at customs. Pay ${amount} to release: {url}",
    # Banking
    "ALERT: Unusual transaction of ${amount} on your {brand} account. Verify: {url}",
    "{brand}: Temporary hold placed on your account. Verify identity: {url}",
    "Your {brand} account will be closed in 24h unless verified: {url}",
    "{brand} FRAUD ALERT: Card charged ${amount}. Dispute at: {url}",
    "IMPORTANT: Your {brand} direct deposit is on hold. Confirm details: {url}",
    "{brand}: We detected a suspicious login from a new device. Verify: {url}",
    "Your {brand} card has been temporarily blocked. Unblock now: {url}",
    # OTP / credential theft
    "Your {brand} security code is {otp}. Enter at {url} to verify. NEVER share this code.",
    "Security code for {brand}: {otp}. Click {url} to complete verification.",
    "{brand} PIN reset: Use {otp} at {url}. Expires in 10 minutes.",
    "Confirm your {brand} account: enter code {otp} at {url}.",
    # Prize / reward
    "CONGRATULATIONS! You've won a {brand} gift card worth $500. Claim at: {url}",
    "You are our lucky winner this week! Collect your ${amount} prize: {url}",
    "{brand} Customer Survey: Selected for a ${amount} reward. Claim: {url}",
    "You have an unclaimed reward from {brand}. Expires today: {url}",
    # Crypto
    "Your {brand} wallet has unconfirmed transactions. Verify now: {url}",
    "Crypto withdrawal pending on {brand}. Confirm your identity: {url}",
    "{brand}: Account flagged for suspicious activity. Secure your funds: {url}",
    "URGENT: {brand} wallet access at risk. Verify ownership now: {url}",
    # Subscription / billing
    "Your {brand} subscription payment failed. Update billing to continue: {url}",
    "{brand}: Your account is about to expire. Renew now: {url}",
    "Final notice: {brand} subscription will cancel unless updated: {url}",
    # Generic urgent
    "URGENT: Your {brand} account requires immediate attention. Act now: {url}",
    "{brand} SECURITY ALERT: Unauthorized access detected. Secure account: {url}",
    "Your {brand} account has been compromised. Verify identity immediately: {url}",
]

SMS_SAFE_TEMPLATES = [
    "Hi {name}, your {brand} order #{tracking} has shipped. Track at https://www.{domain}/track",
    "Hi {name}, your appointment is confirmed for {date} at 10 AM. Reply STOP to cancel.",
    "Reminder: your {brand} bill of ${amount} is due on {date}. Log in at https://www.{domain}/billing",
    "Your {brand} package was delivered to the front door at 2:14 PM. — {brand}",
    "{name}, your verification code is {otp}. This is from {brand} — do not share with anyone.",
    "Hi {name}! Confirming your reservation at The Grand for this Saturday.",
    "{brand}: Your account password was changed. If this wasn't you, call 1-800-{brand_lower}-help.",
    "Hi {name}, road work on Main St tomorrow morning. Plan an alternate route.",
    "Your {brand} refund of ${amount} has been processed. Allow 3-5 business days.",
    "Hi {name}, your {brand} subscription renews on {date} for ${amount}. Manage at https://www.{domain}/billing",
    "{brand}: Your recent purchase of ${amount} was approved. View receipt: https://www.{domain}/receipts",
    "Hi {name}, just a reminder about our call today at 3 PM.",
    "{brand} Rewards: You earned {amount} points on your last purchase.",
    "Hi {name}, your scheduled report is ready at https://www.{domain}/reports",
    "Your {brand} order #{tracking} is out for delivery today.",
    "{name}, your table reservation at {brand} for {date} is confirmed. See you then!",
    "{brand}: Password reset completed. No further action needed.",
    "Hi {name}, the event you registered for starts in 2 hours. Location details attached.",
    "{brand}: Your monthly statement is available at https://www.{domain}/statements",
    "Hi {name}, your trial ends {date}. No action needed — your plan won't change automatically.",
    # Extra safe SMS with security/account language — teaches model these are not exclusive to phishing
    "{brand}: A new login to your account was detected from Chrome on Windows. If this was you, no action needed.",
    "Hi {name}, your {brand} security settings were updated successfully. Manage them at https://www.{domain}/security",
    "{brand}: Your payment of ${amount} was received. Thank you for being a customer.",
    "Hi {name}, your {brand} account statement for {date} is ready. View at https://www.{domain}/account",
    "{brand}: We updated your billing information as requested. No further action needed.",
    "Hi {name}, your identity was verified successfully. You can now access all {brand} features.",
    "{brand}: Your direct deposit of ${amount} has been received and is now available.",
    "Hi {name}, your {brand} card ending in 1234 was used for a purchase of ${amount} on {date}.",
    "{brand}: Your account is in good standing. Next billing date is {date}.",
    "Hi {name}, thanks for updating your payment method on {brand}. Your next bill is due {date}.",
    "{brand}: You have a new message in your account inbox. Log in at https://www.{domain}/messages",
    "Hi {name}, this is a reminder that your {brand} contract renews on {date}.",
    "{brand}: Two-step verification was enabled on your account. Stay secure!",
    "Hi {name}, your support ticket #{tracking} has been resolved. Let us know if you need more help.",
    "{brand}: Your order #{tracking} has been refunded. The ${amount} will appear in 3-5 days.",
]

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _tracking() -> str:
    return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10))

def _amount() -> str:
    return str(random.choice([1,2,3,4,5,9,14,19,29,49,79,99,149,199,249,299,399,499,799,999]))

def _otp() -> str:
    return str(random.randint(100000, 999999))

def _date() -> str:
    day = random.randint(1, 28)
    month = random.choice(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])
    return f"{month} {day}"

def _typo(text: str, prob: float = 0.12) -> str:
    """Inject occasional minor typos to simulate real phishing imperfections."""
    if random.random() < prob:
        # Insert an extra space
        pos = random.randint(0, max(len(text) - 1, 0))
        text = text[:pos] + " " + text[pos:]
    if random.random() < prob * 0.5:
        text = text.rstrip(".") + "..."
    if random.random() < prob * 0.3:
        # lowercase a sentence-starting word
        text = re.sub(r"([.!?]\s+)([A-Z])", lambda m: m.group(1) + m.group(2).lower(), text, count=1)
    return text

def _safe_typo(text: str, prob: float = 0.04) -> str:
    """Very rare typos for safe content."""
    if random.random() < prob:
        pos = random.randint(0, max(len(text) - 1, 0))
        text = text[:pos] + " " + text[pos:]
    return text

import re  # already imported at top but needed locally too

def _phish_url(style: str = "any") -> str:
    r = random.random()
    if style == "shortener" or (style == "any" and r < 0.12):
        s = random.choice(SHORTENERS)
        slug = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(4, 8)))
        return f"https://{s}/{slug}"
    if style == "ip" or (style == "any" and r < 0.22):
        ip = random.choice(IP_ADDRESSES)
        path = random.choice(PHISHING_PATHS)
        return f"http://{ip}{path}"
    if style == "typosquat" or (style == "any" and r < 0.40):
        domain = random.choice(TYPOSQUAT_DOMAINS)
        path = random.choice(PHISHING_PATHS)
        return f"https://{domain}{path}"
    if style == "subdomain" or (style == "any" and r < 0.55):
        prefix = random.choice(SUBDOMAIN_BRAND_PREFIXES)
        attacker = random.choice(ATTACKER_DOMAINS)
        path = random.choice(PHISHING_PATHS)
        return f"https://{prefix}.{attacker}{path}"
    if style == "suspicious_tld" or (style == "any" and r < 0.70):
        words = random.sample(["secure","login","verify","account","auth","confirm","billing","alert","identity","check"], 2)
        base = "-".join(words)
        tld = random.choice(SUSPICIOUS_TLDS_LIST)
        path = random.choice(PHISHING_PATHS)
        q = random.choice([f"?ref={random.randint(1000,9999)}", f"?session=active", f"?token={_otp()}", ""])
        return f"https://{base}{tld}{path}{q}"
    if style == "obfuscated" or (style == "any" and r < 0.82):
        domain = random.choice(SUSPICIOUS_DOMAINS)
        path = random.choice(OBFUSCATED_PATHS)
        return f"https://{domain}{path}"
    if style == "at_symbol" or (style == "any" and r < 0.88):
        domain = random.choice(SUSPICIOUS_DOMAINS)
        path = random.choice(PHISHING_PATHS)
        return f"https://legit-looking.com@{domain}{path}"
    # Default: keyword-stuffed suspicious domain
    domain = random.choice(SUSPICIOUS_DOMAINS)
    path = random.choice(PHISHING_PATHS)
    q = random.choice([f"?redirect=@wallet", "?session=active", f"?ref=validate", f"?id={random.randint(100,999)}", ""])
    return f"https://{domain}{path}{q}"


def _safe_url() -> str:
    r = random.random()
    if r < 0.20:
        brand_name, domain = random.choice(SAFE_BRANDS_URLS)
        path = random.choice(["help","about","search","wiki","blog","news","docs","learn","contribute"])
        return f"https://www.{domain}/{path}"
    if r < 0.35:
        brand_name, domain = random.choice(SAFE_BRANDS_URLS)
        return f"https://{random.choice(SAFE_SUBDOMAINS)}.{domain}/{random.choice(SAFE_PATHS)}"
    # Official brand URL
    brand_name, official_domain = random.choice(BRANDS)
    sub = random.choice(["www"] * 6 + SAFE_SUBDOMAINS)
    path = random.choice(SAFE_PATHS)
    return f"https://{sub}.{official_domain}/{path}"

# ---------------------------------------------------------------------------
# Email generators
# ---------------------------------------------------------------------------

def _phishing_email_body(brand_name: str, phish_url_str: str, subtle: bool = False) -> str:
    greeting = random.choice(PHISHING_GREETINGS)
    urgency = random.choice(PHISHING_URGENCY_SUBTLE if subtle else PHISHING_URGENCY_DIRECT)
    sensitive = random.choice(PHISHING_SENSITIVE)
    closing = random.choice(PHISHING_CLOSINGS)
    link_display = random.choice([
        f"[{brand_name} Support]({phish_url_str})",
        f"[Verify Now]({phish_url_str})",
        f"[Secure Account]({phish_url_str})",
        f"[Click Here]({phish_url_str})",
        f"[Confirm Identity]({phish_url_str})",
        phish_url_str,
    ])

    structures = [
        f"{greeting},\n\n{urgency.capitalize()}. We detected unusual activity on your {brand_name} account. "
        f"Please {sensitive} at {link_display} to avoid restrictions.\n\n{closing}",

        f"{greeting}!\n\nYour {brand_name} account has been compromised. {urgency.capitalize()}. "
        f"Please {sensitive} immediately by visiting {link_display}.\n\n{closing}",

        f"{greeting},\n\n{urgency.capitalize()}. Please {sensitive} to confirm your identity. "
        f"Access your account here: {link_display}\n\n{closing}",

        f"{greeting},\n\nYour {brand_name} subscription requires re-verification. {urgency.capitalize()}. "
        f"{sensitive.capitalize()} via {link_display}.\n\n{closing}",

        f"{greeting},\n\nWe have placed a temporary hold on your {brand_name} account due to {urgency}. "
        f"To restore full access, please {sensitive}: {link_display}\n\n{closing}",

        f"{greeting},\n\nAs part of our security update, all {brand_name} users must {sensitive}. "
        f"{urgency.capitalize()}. Complete verification here: {link_display}\n\n{closing}",

        f"{greeting},\n\nThis is an automated security notice from {brand_name}. "
        f"We have detected {urgency}. Immediate action: {sensitive}. "
        f"Use the link below:\n{link_display}\n\n{closing}",
    ]
    return random.choice(structures)


def generate_phishing_email():
    brand_name, official_domain = random.choice(BRANDS)
    subtle = random.random() < 0.25
    phish = _phish_url()
    body = _typo(_phishing_email_body(brand_name, phish, subtle=subtle))
    sender = random.choice([
        f"alerts.{official_domain.replace('.', '-')}.com",
        f"no-reply.{brand_name.lower().replace(' ', '')}-secure.com",
        f"security@{random.choice(SUSPICIOUS_DOMAINS)}",
        f"support@{random.choice(TYPOSQUAT_DOMAINS)}",
        f"noreply@verify-{brand_name.lower().replace(' ', '')}.com",
        random.choice(SUSPICIOUS_DOMAINS),
    ])
    return body, brand_name, sender


def generate_safe_email():
    brand_name, official_domain = random.choice(BRANDS)
    name = random.choice(SAFE_NAMES)
    greeting = random.choice(SAFE_GREETINGS).format(name=name)

    roll = random.random()
    if roll < 0.12:
        body_text = random.choice(SAFE_NEWSLETTER_BODIES).format(
            domain=official_domain, brand=brand_name
        )
    elif roll < 0.28:
        body_text = random.choice(SAFE_URGENT_BODIES).format(
            domain=official_domain, date=_date(), brand=brand_name
        )
    elif roll < 0.45:
        # Borderline safe — has security/account/payment language but is legit
        body_text = random.choice(SAFE_BORDERLINE_BODIES).format(
            name=name, brand=brand_name, domain=official_domain,
            amount=_amount(), date=_date(), tracking=_tracking()
        )
    else:
        body_text = random.choice(SAFE_EMAIL_BODIES).format(
            domain=official_domain, tracking=_tracking(),
            date=_date(), brand=brand_name, amount=_amount()
        )

    closing = random.choice(SAFE_CLOSING_VARIANTS).format(brand=brand_name)
    body = f"{greeting},\n\n{body_text}\n\n{closing}"
    body = _safe_typo(body)

    sender = official_domain if random.random() < 0.65 else random.choice(FREE_MAIL)
    claimed_brand = brand_name if random.random() < 0.70 else ""
    return body, claimed_brand, sender

# ---------------------------------------------------------------------------
# SMS generators
# ---------------------------------------------------------------------------

def generate_phishing_sms():
    brand_name, official_domain = random.choice(BRANDS)
    phish = _phish_url()
    tpl = random.choice(SMS_PHISHING_TEMPLATES)
    body = tpl.format(
        brand=brand_name,
        tracking=_tracking(),
        amount=_amount(),
        otp=_otp(),
        url=phish,
        domain=official_domain,
        brand_lower=brand_name.lower().replace(" ", ""),
    )
    body = _typo(body)
    sender = random.choice(SUSPICIOUS_DOMAINS + ["short-code-alert.com","sms-notify.net","txt-verify.net","alert-sms.co"])
    return body, brand_name, sender


def generate_safe_sms():
    name = random.choice(SAFE_NAMES)
    brand_name, official_domain = random.choice(BRANDS)
    tpl = random.choice(SMS_SAFE_TEMPLATES)
    body = tpl.format(
        name=name,
        brand=brand_name,
        tracking=_tracking(),
        domain=official_domain,
        amount=_amount(),
        date=_date(),
        otp=_otp(),
        brand_lower=brand_name.lower().replace(" ", ""),
    )
    body = _safe_typo(body)
    sender = random.choice(FREE_MAIL + ["notify.carrier.com","txt-service.net","alerts.mobile.com"])
    return body, "", sender


# ---------------------------------------------------------------------------
# URL edge-case generators (borderline samples)
# ---------------------------------------------------------------------------

def generate_borderline_phish_url() -> str:
    """URLs that look somewhat legitimate but have one or two red flags."""
    style = random.choice(["typosquat","suspicious_tld","subdomain"])
    return _phish_url(style=style)


def generate_borderline_safe_url() -> str:
    """Legitimate URLs with account/billing/security paths that look like
    phishing paths but belong to known-safe domains — teaches the URL model
    that these path keywords alone are not sufficient for a phishing verdict."""
    r = random.random()
    if r < 0.5:
        brand_name, official_domain = random.choice(BRANDS)
        # Use paths that mirror phishing paths but on real domains
        path = random.choice([
            "account/security", "account/billing", "account/payments",
            "account/verify", "account/confirm", "billing/update",
            "security/settings", "login", "signin", "reset-password",
            "account/login", "verify-email", "account/signin",
        ])
        q = random.choice([
            f"?ref={random.randint(1000,9999)}",
            f"?tab=billing", f"?from=email&campaign=reminder",
            f"?locale=en-US", "",
        ])
        sub = random.choice(["www","help","support","accounts","mail","secure"])
        return f"https://{sub}.{official_domain}/{path}{q}"
    else:
        brand_name, official_domain = random.choice(BRANDS)
        path = random.choice(SAFE_PATHS)
        q = random.choice([
            f"?ref={random.randint(1000,9999)}", f"?tab=billing",
            f"?from=email&campaign=reminder", f"?locale=en-US", "",
        ])
        sub = random.choice(["www","help","support","accounts","mail"])
        return f"https://{sub}.{official_domain}/{path}{q}"

# ---------------------------------------------------------------------------
# Main — build and write the dataset
# ---------------------------------------------------------------------------

def main() -> None:
    rows: list[dict] = []

    # ── Phishing emails (3,000) ───────────────────────────────────────────
    for _ in range(3000):
        content, brand, sender = generate_phishing_email()
        rows.append({"content": content, "content_type": "email", "label": 1,
                     "claimed_brand": brand, "sender_domain": sender})

    # ── Safe emails (3,000) ───────────────────────────────────────────────
    for _ in range(3000):
        content, brand, sender = generate_safe_email()
        rows.append({"content": content, "content_type": "email", "label": 0,
                     "claimed_brand": brand, "sender_domain": sender})

    # ── Phishing SMS (1,000) ──────────────────────────────────────────────
    for _ in range(1000):
        content, brand, sender = generate_phishing_sms()
        rows.append({"content": content, "content_type": "sms", "label": 1,
                     "claimed_brand": brand, "sender_domain": sender})

    # ── Safe SMS (1,000) ──────────────────────────────────────────────────
    for _ in range(1000):
        content, brand, sender = generate_safe_sms()
        rows.append({"content": content, "content_type": "sms", "label": 0,
                     "claimed_brand": brand, "sender_domain": sender})

    # ── Phishing URLs (3,400) ─────────────────────────────────────────────
    # Mix of styles to cover all URL feature signals
    url_styles = (
        ["shortener"]    * 340 +   # 10%
        ["ip"]           * 340 +   # 10%
        ["typosquat"]    * 680 +   # 20%
        ["subdomain"]    * 680 +   # 20%
        ["suspicious_tld"] * 680 + # 20%
        ["obfuscated"]   * 340 +   # 10%
        ["at_symbol"]    * 170 +   # 5%
        ["any"]          * 170     # 5% mixed
    )
    random.shuffle(url_styles)
    for style in url_styles:
        rows.append({"content": _phish_url(style=style), "content_type": "url", "label": 1,
                     "claimed_brand": "", "sender_domain": ""})

    # Extra borderline phishing URLs (useful for teaching subtle signals)
    for _ in range(170):
        rows.append({"content": generate_borderline_phish_url(), "content_type": "url", "label": 1,
                     "claimed_brand": "", "sender_domain": ""})

    # ── Safe URLs (3,400) ─────────────────────────────────────────────────
    for _ in range(2900):
        rows.append({"content": _safe_url(), "content_type": "url", "label": 0,
                     "claimed_brand": "", "sender_domain": ""})

    # Borderline safe URLs: real domains with account/billing/security paths
    # — teaches the URL model that these path words alone are not phishing
    for _ in range(500):
        rows.append({"content": generate_borderline_safe_url(), "content_type": "url", "label": 0,
                     "claimed_brand": "", "sender_domain": ""})

    # ── Shuffle and write ─────────────────────────────────────────────────
    random.shuffle(rows)

    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["content", "content_type", "label", "claimed_brand", "sender_domain"]
    with open(DATASET_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    labels = [r["label"] for r in rows]
    types  = [r["content_type"] for r in rows]
    print(f"\nDataset written → {DATASET_PATH}")
    print(f"Total samples : {total}")
    print(f"  Phishing    : {labels.count(1)}")
    print(f"  Safe        : {labels.count(0)}")
    for t in ["email", "url", "sms"]:
        tc = types.count(t)
        ph = sum(1 for r in rows if r["content_type"] == t and r["label"] == 1)
        sa = sum(1 for r in rows if r["content_type"] == t and r["label"] == 0)
        print(f"  {t:6s}: {tc:5d}  (phishing {ph}, safe {sa})")


if __name__ == "__main__":
    main()

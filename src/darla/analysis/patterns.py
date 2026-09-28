"""Pre-compiled regex patterns for IOC extraction from phishing kit source files."""

import re
from urllib.parse import urlparse

# Increment when patterns, allowlists, or extraction logic change.
# Used to identify kits that need re-analysis after updates.
PATTERN_VERSION = 5

# ---------- Email addresses ----------
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
EMAIL_EXCLUSIONS = {
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "w3.org", "jquery.com", "google.com", "gmail.com", "schema.org",
    "apache.org", "mozilla.org", "php.net", "github.com",
    "wordpress.org", "gravatar.com", "fontawesome.com",
    "microsoft.com", "apple.com", "icloud.com",
    "w3schools.com", "stackoverflow.com", "npmjs.com",
    "bootstrap.com", "getbootstrap.com",
    "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "protonmail.com", "zoho.com",
    # Placeholder / template domains
    "mysite.com", "abc.com", "domain.com", "yoursite.com", "site.com",
    "email.com", "yourdomain.com", "company.com", "sampleemail.com",
}

# Placeholder email local parts — these are never real exfil targets
EMAIL_PLACEHOLDER_LOCALS = {
    "your", "user", "username", "name", "email", "test", "admin",
    "info", "support", "contact", "hello", "example", "sample",
    "your.email", "your.name", "youremail", "eg.user",
}

# ---------- Telegram Bot Tokens ----------
# Format: {bot_id}:{token} where bot_id is 8-10 digits
TELEGRAM_BOT_TOKEN_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])\d{8,10}:[0-9A-Za-z_-]{35}(?![a-zA-Z0-9])",
)

# ---------- Telegram Chat IDs ----------
TELEGRAM_CHAT_ID_PATTERN = re.compile(
    r'(?:chat_id|chatid|chat)["\s:=]+(-?\d{6,14})',
    re.IGNORECASE,
)

# ---------- C2 / Exfiltration URLs ----------
C2_URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,500}",
    re.IGNORECASE,
)
WEBSOCKET_URL_PATTERN = re.compile(
    r"wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,500}",
    re.IGNORECASE,
)
# Strip trailing syntax junk that the broad regex consumes
URL_TRAILING_JUNK = re.compile(r"['\";,)\]}>\\]+$")

# CSS selector fragments that leak into URL matches (e.g. "tailwindcss.com*/*,:after,:before")
CSS_JUNK_IN_URL = re.compile(
    r"[*{}<>]|::?(?:before|after|hover|focus|active|visited|placeholder|root)"
)

# JS string concatenation boundary — URL should be truncated here
# Matches '+, "+, `,  which indicate the URL literal has ended and JS code follows
JS_CONCAT_BOUNDARY = re.compile(r"""['"]\s*\+|['"]\s*,\s*['"]""")

TELEGRAM_API_PATTERN = re.compile(
    r"https?://api\.telegram\.org/bot[0-9A-Za-z_\-:/]+",
    re.IGNORECASE,
)

# Benign root domains — extract the registrable domain from a URL and check
# membership. Uses root-domain matching (e.g. "docs.google.com" → "google.com").
BENIGN_URL_ROOT_DOMAINS = frozenset({
    # Google ecosystem
    "google.com", "google.co.uk", "google.co.jp", "google.de", "google.fr",
    "google.co.in", "google.com.br", "google.com.au",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "googlesyndication.com", "googletagmanager.com", "google-analytics.com",
    "doubleclick.net", "withgoogle.com", "ggpht.com", "gvt1.com",
    "gvt2.com", "googlevideo.com", "googleadservices.com",
    # Microsoft ecosystem
    "microsoft.com", "microsoftonline.com", "windows.net", "azure.com",
    "azureedge.net", "office.com", "office365.com", "live.com",
    "outlook.com", "bing.com", "msn.com", "hotmail.com",
    "windowsupdate.com", "visualstudio.com",
    "msftauth.net", "msauth.net", "msftauthimages.net",
    "s-microsoft.com", "microsoft.cloud", "xbox.com",
    "microsoftonline-p.com", "microsoftazuread-sso.com",
    "logincdn.msftcloudes.com", "azure-api.net",
    "onmicrosoft.com", "sharepoint.com", "onenote.com",
    "skype.com", "teams.microsoft.com",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "amazontrust.com", "cloudfront.net",
    "awsstatic.com",
    # CDNs
    "cloudflare.com", "cloudflare-dns.com",
    # Cloudflare Web Analytics beacon (static.cloudflareinsights.com) —
    # auto-injected on Cloudflare-proxied sites, including phish.
    "cloudflareinsights.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaitechnologies.com",
    "fastly.net", "fastlycdn.com",
    "bootstrapcdn.com", "stackpath.com", "stackpathcdn.com",
    # Libraries / frameworks
    "jquery.com", "getbootstrap.com", "tailwindcss.com", "fontawesome.com",
    "reactjs.org", "vuejs.org", "angular.io",
    # Site builders / hosting platforms
    "weebly.com", "weeblysite.com", "editmysite.com",
    "wix.com", "wixsite.com", "wixstatic.com", "wixapps.net",
    "parastorage.com", "wixmp.com", "wixpress.com", "wl.co",
    "wix-code.com", "wixstudio.com", "filesusr.com",
    "strikingly.com", "mystrikingly.com",
    "squarespace.com", "sqspcdn.com",
    "square.online", "squareup.com",
    "wordpress.com", "wordpress.org", "wp.com", "wpcomstaging.com", "w.org",
    "shopify.com", "shopifycdn.com", "shopifyanalytics.com",
    "webflow.com", "webflow.io", "website-files.com",
    "godaddy.com", "secureserver.net",
    "hostinger.com", "bluehost.com",
    "framer.com", "framerusercontent.com",
    # Code hosting / docs
    "github.com", "github.io", "githubusercontent.com", "githubassets.com",
    "gitlab.com", "gitlab.io",
    "gitbook.io", "gitbook.com",
    "bitbucket.org",
    "readthedocs.io", "readthedocs.org",
    # Social media
    "facebook.com", "fbcdn.net", "fbsbx.com",
    "twitter.com", "x.com", "twimg.com",
    "twitch.tv", "twitchcdn.net",
    "instagram.com", "cdninstagram.com",
    "linkedin.com", "licdn.com",
    "youtube.com", "youtu.be", "ytimg.com",
    "vimeo.com", "vimeocdn.com",
    "tiktok.com", "tiktokcdn.com",
    "reddit.com", "redditmedia.com", "redditstatic.com",
    "pinterest.com", "pinimg.com",
    "tumblr.com",
    "discord.com", "discord.gg", "discordapp.com",
    "whatsapp.com",
    # SaaS / productivity
    "zoom.us", "zoom.com", "zoomcdn.com",
    "calendly.com",
    "jotform.com", "jotfor.ms",
    "typeform.com",
    "mailchimp.com",
    "slack.com", "slack-imgs.com",
    "notion.so", "notion.site",
    "canva.com",
    "figma.com",
    "atlassian.com", "atlassian.net",
    # Form / survey platforms
    "surveymonkey.com", "surveygizmo.com",
    "qualtrics.com",
    # Gaming platforms (phishing targets — their own assets aren't IOCs)
    "roblox.com", "rbxcdn.com",
    "steampowered.com", "steamcommunity.com", "steamstatic.com",
    "epicgames.com",
    "ea.com",
    # Email providers
    "yahoo.com", "yahoo.co.jp", "yahoo.co.kr", "yimg.com",
    "protonmail.com", "proton.me",
    "zoho.com",
    "mail.ru",
    # Payment / finance (targets, not actor infra)
    "paypal.com", "paypalobjects.com",
    "stripe.com", "stripe.network",
    "venmo.com",
    # E-commerce (cloned targets)
    "ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr",
    # Cloud storage (targets, not actor infra)
    "dropbox.com", "dropboxusercontent.com", "dropboxstatic.com",
    "box.com",
    "onedrive.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    # Standards / reference
    "w3.org", "w3schools.com",
    "schema.org", "json-schema.org",
    "php.net", "apache.org", "mozilla.org", "mozilla.net",
    "stackoverflow.com", "stackexchange.com",
    "npmjs.com", "yarnpkg.com",
    "quirksmode.org",
    # Captcha / anti-bot
    "recaptcha.net", "hcaptcha.com",
    # Analytics
    "segment.io", "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "newrelic.com",
    # Blogging / CMS
    "blogger.com", "blogspot.com",
    # Travel / booking (targets, not actor infra)
    "booking.com", "bstatic.com",
    # URL shorteners / link management
    "bitly.com", "bit.ly",
    "ead.me",
    "goo.gl", "linktr.ee",
    # Security vendors
    "fortinet.com",
    # Consent / cookie management
    "cookielaw.org", "onetrust.com",
    # Monitoring / observability
    "datadoghq.com", "datadoghq-browser-agent.com",
    "heapanalytics.com",
    # SaaS link pages
    "flowcode.com", "campsite.bio", "campsite.to",
    # Website builders (additional)
    "webador.com",
    # Standards / specifications
    "sil.org", "gmpg.org", "ogp.me",
    "example.com",
    # Other benign
    "archive.org", "pearltrees.com", "metamask.io",
    "clearbit.com", "forms.app", "cpanel.net", "crazydomains.com",
    "nflxext.com", "fontsquirrel.com", "prismic.io", "opengraph.org",
    "ipify.org", "editor.website",
    "nr-data.net", "gsap.to",
    "gravatar.com",
    "cloudinary.com",
    "sentry.io",
    "qualified.com",
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "hubspot.com", "hsforms.com", "hubspotusercontent.com",
    "activecampaign.com",
    "pxf.io", "shareasale.com", "impact.com",
    "tistory.com",
    "qr-code-generator.com",
    "n9.cl",
    "offset.com",
    "edgecastcdn.net",
    "vk-portal.net",
    "latofonts.com",
})

# Two-part country-code SLDs (e.g. .co.uk, .com.br) — need 3 labels for root domain
_TWO_PART_TLDS = frozenset({
    "co.uk", "co.jp", "co.kr", "co.in", "co.nz", "co.za", "co.id",
    "com.au", "com.br", "com.mx", "com.ar", "com.co", "com.tr",
    "com.sg", "com.my", "com.ph", "com.pk", "com.ng", "com.eg",
    "org.uk", "org.au", "net.au", "gov.uk", "ac.uk",
    "ne.jp", "or.jp", "go.jp",
})


def extract_root_domain(hostname: str) -> str:
    """Extract the registrable root domain from a hostname.

    Examples:
        "docs.google.com" → "google.com"
        "cdn.jsdelivr.net" → "jsdelivr.net"
        "foo.co.uk" → "foo.co.uk"
    """
    hostname = hostname.lower().rstrip(".")
    parts = hostname.split(".")
    if len(parts) >= 3:
        last_two = ".".join(parts[-2:])
        if last_two in _TWO_PART_TLDS:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


_HTML_ENTITY_RE = re.compile(r"&[a-zA-Z]+;?|&#[0-9]+;?|&#x[0-9a-fA-F]+;?")


def is_benign_url(url: str) -> bool:
    """Check if a URL belongs to a known benign service."""
    try:
        # Strip HTML entities that corrupt urlparse (e.g. &quot; &amp;)
        clean_url = _HTML_ENTITY_RE.sub("", url)
        hostname = urlparse(clean_url).hostname
        if not hostname:
            return False
        root = extract_root_domain(hostname)
        return root in BENIGN_URL_ROOT_DOMAINS
    except Exception:
        return False


# Resource origin classification — used by the IOC scanner to decide whether
# a browser-captured file should be regex-scanned at all.  Attacker-served
# JS still goes through the full extractor; jQuery-from-a-CDN doesn't.
ORIGIN_BENIGN = "benign"       # served by a known-legitimate CDN/SaaS
ORIGIN_LURE = "lure"           # served by the lure domain (attacker page)
ORIGIN_UNKNOWN = "unknown"     # unclassified — scan as normal


def classify_origin(origin_url: str, lure_root_domain: str | None = None) -> str:
    """Classify an origin URL for IOC-extraction gating.

    Returns one of ``ORIGIN_BENIGN``, ``ORIGIN_LURE``, ``ORIGIN_UNKNOWN``.
    Callers skip content-regex IOC scans for ``ORIGIN_BENIGN`` files.
    """
    if not origin_url:
        return ORIGIN_UNKNOWN
    try:
        clean_url = _HTML_ENTITY_RE.sub("", origin_url)
        hostname = urlparse(clean_url).hostname
    except Exception:
        return ORIGIN_UNKNOWN
    if not hostname:
        return ORIGIN_UNKNOWN
    root = extract_root_domain(hostname.lower())
    if root in BENIGN_URL_ROOT_DOMAINS:
        return ORIGIN_BENIGN
    if lure_root_domain and root == lure_root_domain:
        return ORIGIN_LURE
    return ORIGIN_UNKNOWN


# URL path patterns that indicate static assets (not C2)
BENIGN_URL_EXTENSIONS = frozenset({
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".map", ".min.js", ".min.css",
    ".js",  # standalone .js files are library assets, not C2 endpoints
    ".mp3", ".mp4", ".webm", ".ogg",
    ".pdf",
})

# ---------- AiTM Auth Endpoints ----------
# Real authentication endpoints that AiTM kits proxy through attacker domains.
# If an HTML page on a non-Microsoft/Google domain references these, it's proxying.
AITM_AUTH_ENDPOINTS = frozenset({
    "login.microsoftonline.com",
    "login.microsoft.com",
    "accounts.google.com",
    "login.live.com",
    "login.windows.net",
    "sts.windows.net",
    "aadcdn.msauth.net",
    "aadcdn.msftauth.net",
})

# C2/exfil keywords that boost confidence — must be specific to phishing
# infrastructure, NOT generic web terms like "login" or "submit" that match
# every legitimate login page a kit impersonates.
C2_KEYWORDS = {
    "exfil", "steal", "grab", "gate",
    "next.php", "post.php", "done.php", "finish.php",
    "send.php", "save.php", "log.php", "gate.php",
    "panel.php", "result.php", "collect.php",
    "bot_token", "chat_id", "sendMessage",
    "telegram.org/bot",
}

# ---------- PHP mail() function patterns ----------
PHP_MAIL_PATTERN = re.compile(
    r"mail\s*\(\s*['\"]([^'\"]+@[^'\"]+)['\"]",
    re.IGNORECASE,
)
PHP_MAIL_TO_PATTERN = re.compile(
    r"\$(?:to|recipient|email_to|sendto)\s*=\s*['\"]([^'\"]+@[^'\"]+)['\"]",
    re.IGNORECASE,
)

# ---------- IP Addresses (IPv4) ----------
# Each octet must be 1-3 digits with NO leading zero (rejects 21.061.065.065).
# Boundary lookarounds exclude digits, dots, and hyphen-digit patterns so
# version strings embedded in filenames/URLs like "-1.2.1.1-" don't match.
IPV4_PATTERN = re.compile(
    r"(?<![0-9.\-])"
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)"
    r"(?![0-9.\-])",
)
PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "0.", "169.254.")

# Filename/path fragments that signal a Cloudflare challenge HTML or script.
# Challenge pages contain Base58-ish ray tokens that trip the Bitcoin regex
# and embedded version strings (e.g. "-1.2.1.1-") that trip the IPv4 regex.
CLOUDFLARE_CHALLENGE_FILENAME_RE = re.compile(
    r"-\d{10}-\d+\.\d+\.\d+\.\d+-",
)

# Path fragments of third-party "what's my IP" services.  The response body
# is the *visitor's* public IP, not attacker infrastructure — IP extraction
# on these responses produces a guaranteed false positive.
IP_ECHO_FILENAME_FRAGMENTS = (
    "api.ipify.org",
    "ipapi.co",
    "ipinfo.io",
    "api.ipbase.com",
    "api.ip.sb",
    "ifconfig.me",
    "icanhazip.com",
)

# Keyword window for Telegram handle extraction.  A bare "@handle" match is
# only promoted to a Telegram IOC if one of these markers appears nearby on
# the same line — otherwise it's almost always a JS decorator, CSS at-rule,
# JSON-LD key, or minified symbol.
TELEGRAM_CONTEXT_MARKERS = (
    "telegram", "t.me/", "t.me\\/", "tg://", "tg:\\/\\/",
    "telegra.ph", "@telegram", "telegrambot", "telegram_channel",
    "telegram bot", "telegram chat",
)

# ---------- SMTP Credentials ----------
# Require PHP variable assignment ($var = "val") or array/config key syntax
# ("key" => "val" / "key": "val").  Values must be quoted and ≥3 chars to
# filter HTML attribute junk (name=, class=, placeholder=) and short English
# words (is, to, was) that the old broad pattern captured.
SMTP_HOST_PATTERN = re.compile(
    r"""\$(?:smtp_?host|smtp_?server|mail_?host)\s*=\s*["']([a-zA-Z0-9.\-]{3,}\.[a-zA-Z]{2,})["']"""
    r"""|["'](?:smtp_?host|smtp_?server|mail_?host)["']\s*(?:=>|:)\s*["']([a-zA-Z0-9.\-]{3,}\.[a-zA-Z]{2,})["']""",
    re.IGNORECASE,
)
SMTP_USER_PATTERN = re.compile(
    r"""\$(?:smtp_?user(?:name)?|mail_?user)\s*=\s*["']([^"']{3,})["']"""
    r"""|["'](?:smtp_?user(?:name)?|mail_?user)["']\s*(?:=>|:)\s*["']([^"']{3,})["']""",
    re.IGNORECASE,
)
SMTP_PASS_PATTERN = re.compile(
    r"""\$(?:smtp_?pass(?:word)?|mail_?pass(?:word)?)\s*=\s*["']([^"']{3,})["']"""
    r"""|["'](?:smtp_?pass(?:word)?|mail_?pass(?:word)?)["']\s*(?:=>|:)\s*["']([^"']{3,})["']""",
    re.IGNORECASE,
)

# SMTP host values that are SaaS platforms or JS variables, not real SMTP hosts
SMTP_HOST_EXCLUSIONS = frozenset({
    "app.jotform.com", "jotform.com",
    "t.host", "this.host", "e.host", "a.host",  # JS variable access
})

# ---------- Cryptocurrency Wallets ----------
BITCOIN_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![a-zA-Z0-9])"
)
ETHEREUM_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])0x[0-9a-fA-F]{40}(?![a-zA-Z0-9])"
)

# ---------- Domain Names ----------
# Standalone domain references — multi-label domains like smtp.evil-mailer.org
# Lookbehind blocks alphanumeric, slashes, and URL-path chars to prevent
# matching fragments inside URLs (e.g. "orkspace.google.com" from https://workspace...)
DOMAIN_PATTERN = re.compile(
    r'(?<![a-zA-Z0-9/\-_%.:])'
    r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,6})'
    r'(?![/\w.])',
    re.IGNORECASE,
)
# File extensions that look like TLDs but aren't domains
FALSE_DOMAIN_EXTENSIONS = {
    ".php", ".js", ".css", ".html", ".htm", ".json", ".xml",
    ".txt", ".png", ".jpg", ".gif", ".svg", ".ico", ".map",
    ".min", ".inc", ".conf", ".ini", ".log", ".sql", ".bak",
}
# Real TLDs — only extract domains whose final label is in this set
VALID_TLDS = {
    # Generic
    "com", "org", "net", "edu", "gov", "mil", "int",
    # Common gTLDs
    "io", "co", "me", "info", "biz", "name", "pro", "mobi", "tel", "asia",
    "xyz", "online", "site", "store", "app", "dev", "cloud", "tech", "live",
    "shop", "club", "fun", "space", "top", "work", "click", "link", "help",
    "news", "world", "today", "life", "website", "host", "email", "page",
    "solutions", "zone", "agency", "digital", "media", "center", "network",
    # Country codes (most common)
    "us", "uk", "ca", "au", "de", "fr", "it", "es", "nl", "be", "ch", "at",
    "ru", "cn", "jp", "kr", "in", "br", "mx", "za", "ng", "ke", "eg",
    "pl", "cz", "se", "no", "dk", "fi", "pt", "ie", "nz", "sg", "hk",
    "tw", "th", "ph", "id", "my", "vn", "pk", "bd", "ar", "cl",
    "pe", "ve", "ua", "ro", "hu", "bg", "hr", "sk", "si", "lt", "lv",
    "ee", "is", "lu", "gr", "tr", "il", "ae", "sa", "qa",
    # Phishing-popular free/cheap TLDs
    "tk", "ml", "ga", "cf", "gq", "buzz", "rest", "surf", "icu",
    "cc", "ws", "pw", "to", "ly", "su", "la", "nu",
    # Additional
    "sbs", "cfd", "cyou", "best",
}
# JS property accesses that happen to have valid TLDs (e.g. navigator.online)
JS_FALSE_DOMAINS = {
    "navigator.online", "window.location", "document.domain",
    "window.top", "window.name", "self.name", "parent.top",
    "screen.info", "history.link", "location.host", "location.site",
    "window.site", "document.link", "element.click", "event.page",
    "document.page", "window.app", "window.dev",
    # Additional observed false positives
    "object.is", "x22object.is", "link.click",
    "el-descriptions--mini.is",
    "locale-dataset.countries.com",
    # Observed from production data — JS property access + ccTLD
    "window.ga", "window.console.info",
    "window.analytics.page", "window.shopifyanalytics.lib.page",
    "window.langconfig.id", "window.vk.id",
    "thirdparty.is",
    "linkel.media",
    # JS builtins that look like domains
    "console.info", "console.log", "console.error",
    # HTML elements parsed as domains
    "td.info", "th.info", "tr.info", "tr.in", "td.in", "th.in",
    "tbody.in", "thead.in", "tfoot.in",
    "loc.host", "custom.host",
}
# JS object prefixes — any domain starting with these followed by a dot
# is almost certainly a property access, not a real domain
_JS_OBJECT_PREFIXES = (
    "this.", "self.", "window.", "document.", "navigator.",
    "element.", "event.", "error.", "screen.", "history.",
    "location.", "parent.", "caller.", "button.", "input.",
    "form.", "link.", "file.", "cookie.", "entry.",
    "source.", "asset.", "media.", "place.", "attr.",
    "attribute.", "item.", "data.", "browser.", "object.",
    # HTML elements that get parsed as domain prefixes
    "tbody.", "thead.", "tfoot.", "field.",
)
# TLDs that are overwhelmingly JS false positives when paired with
# single-word object names (e.g. this.br, caller.name, rootdiv.id)
_JS_PRONE_TLDS = frozenset({
    "name", "id", "is", "at", "br", "ml", "lt", "es", "ee",
    "no", "me", "to", "au", "in", "my", "qa", "ph", "pt",
    "ga", "info", "page", "host", "click", "link", "top",
    "center", "media",
    # Additional ccTLDs that collide with JS attribute/property names
    # (he.name, ge.th, bz.jp, cg.bd, cg.be) and gTLDs that look like
    # object keys (ai.info, ce.top, mt.host).
    "th", "jp", "bd", "be",
})
# Benign domains to skip in standalone domain extraction.
# Uses root-domain matching via extract_root_domain() — so adding "google.com"
# covers docs.google.com, meet.google.com, etc.
BENIGN_DOMAINS = BENIGN_URL_ROOT_DOMAINS | EMAIL_EXCLUSIONS

# ---------- Phone Numbers ----------
# Matches international format: +CC (optional area) subscriber
# Requires balanced parens; digit count validated in extractor (7-13).
PHONE_PATTERN = re.compile(
    r"(?<![0-9a-zA-Z])"
    r"\+\d{1,3}"                      # country code
    r"(?:[\s\-]?\(\d{1,4}\))??"       # optional (area) — balanced parens
    r"(?:[\s\-]?\d{1,5}){1,4}"        # subscriber groups
    r"(?![0-9a-zA-Z).])"
)

# ---------- Telegram Handles ----------
TELEGRAM_HANDLE_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])@([a-zA-Z][a-zA-Z0-9_]{4,31})(?![a-zA-Z0-9_])"
)
# Handles shared as a Telegram profile URL: https://t.me/{handle},
# https://telegram.me/{handle}.  Captured in addition to the bare "@handle"
# form since many panels/phishing kits only link via URL.
TELEGRAM_URL_HANDLE_PATTERN = re.compile(
    r"(?:https?:\\?/\\?/)?(?:www\.)?t(?:elegram)?\.me\\?/([a-zA-Z][a-zA-Z0-9_]{4,31})(?![a-zA-Z0-9_])",
    re.IGNORECASE,
)
# Common false positives for @handles (CSS/JS/email/JSON-LD/npm conventions)
TELEGRAM_HANDLE_EXCLUSIONS = {
    # CSS at-rules / directives
    "media", "keyframes", "import", "charset", "supports",
    "layer", "scope", "container", "property",
    "apply", "screen", "tailwind", "responsive",
    # CSS/JS event/action keywords
    "click", "start", "input", "change", "focus", "submit",
    "scroll", "resize", "error", "reset", "select", "toggle",
    "ended", "abort",
    # JSDoc / Java annotations
    "param", "return", "throws", "override", "deprecated",
    "author", "version", "license", "copyright", "since",
    # License comment markers
    "licstart", "licend",
    # Email providers
    "gmail", "yahoo", "outlook", "hotmail",
    # JSON-LD keywords
    "context", "graph", "type", "value", "vocab", "reverse", "language",
    # npm scopes / JS frameworks
    "formatjs", "babel", "types", "angular", "react", "emotion",
    "popperjs", "floating-ui",
    # JS builtins / methods
    "iterator", "generator", "asynciterator", "tostringtag",
    "toprimitive", "tostring", "valueof", "hasinstance",
    # SaaS / brand names (observed in production)
    "flowcode", "getflowcode", "newrelic", "fontawesome", "roblox",
    "prezoai", "glimitedaccount", "typedreamhq", "cakeresume",
    "aboutdotme", "ghost", "dropbox", "miricanvas", "lottiefiles",
    "activecampaign", "lemonde", "lemonde_en", "yahoo_japan_pr",
    "plesk", "wordpress", "squarespace", "hubspot", "mailchimp",
    "sendgrid", "intercom", "zendesk",
    # Generic UI / platform terms
    "overview", "conference", "widget", "forms", "formsapp",
    "everyone", "channel", "here",
    # Font-face descriptor
    "font-face",
}

import re
import urlextract
from urllib.parse import urlparse

#set of known suspicious Top Level Domians
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".info", ".biz",
    ".pw", ".cc", ".ws", ".ru", ".cn",
    ".zip", ".mov", ".work", ".link",
    ".click", ".review", ".loan", ".download", ".stream"
}

#List of well known brands
BRAND_KEYWORDS = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "whatsapp", "telegram", "yahoo", "outlook",
    "office365", "onedrive", "icloud", "ebay", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "dhl", "fedex", "ups", "usps", "steam", "discord"
]

def analyze_url(url: str) -> dict:
    findings = {}
    extracted = tldrxtract.extract(url)
    parsed = urlparse(url)

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    #Chechink length of the url
    url_length = len(url)
    findings['url length'] = {
        'label':'URL Length',
        'value':url_length,
        'flagged': url_length > 75,
        'score': 15 if url_length > 75 else 0,
        'detail':f"{url_length} characters - {'suspicious (>75)' if url_length > 75 else 'normal'}"
    }

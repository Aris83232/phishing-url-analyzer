import whois
import tldextract
from datetime import datetime, timezone

def check_domain_age(url: str) -> dict:
    try:
        tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        w = whois.whois(domain)

        if instance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {
                'flagged': True,
                'score': 20,
                'detail': "Creation date coudn't be retrieved, will be flagged suspicious",
                'domain': domain,
                'age_days': None
            }
        
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days
        flagged = age_days < 30

        return {
                'flagged': "flagged",
                'score': 25 if age_days < 30 else (10 if age_days < 100 else 0),
                'detail': f"Domain '{domain}' is {age_days} old - {'NEWLY REGISTERED (high risk)' if age_days < 30 else 'Normal'}",
                'domain': domain,
                'age_days': age_days
            }

    except Exception as e:
        return {
                'flagged': True,
                'score': 15,
                'detail': f"WHOIS lookup failed: {str(e)}",
                'domain': url,
                'age_days': None
            }
import urllib.parse
import hashlib

def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception as e:
        print(f"Error extracting domain: {e}")
        return url

def check_https(url):
    return url.startswith('https://')

def get_simulated_domain_age(domain):
    # Deterministic hash for age 1-9999
    hash_obj = hashlib.md5(domain.encode())
    return (int(hash_obj.hexdigest(), 16) % 9999) + 1

def detect_suspicious_patterns(url):
    patterns = []
    if any(kw in url.lower() for kw in ['login', 'password', 'verify', 'account', 'secure', 'billing']):
        patterns.append("Login/security keywords in URL")
    
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf']
    if any(url.endswith(tld) or (tld + '/') in url for tld in suspicious_tlds):
        patterns.append("Suspicious TLD detected")
        
    domain = extract_domain(url)
    if domain.count('.') >= 3:
        patterns.append("Excessive subdomains detected")
        
    # Check if domain is an IP address
    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        patterns.append("IP address used as domain")
        
    return patterns

def count_trackers(domain):
    # Deterministic hash for tracker count 0-7
    hash_obj = hashlib.md5(domain.encode())
    return int(hash_obj.hexdigest(), 16) % 8

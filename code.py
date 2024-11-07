import re
import requests
import tldextract
from urllib.parse import urlparse

# List of common phishing URL patterns or suspicious keywords
phishing_keywords = ['login', 'secure', 'account', 'verify', 'signin', 'bank', 'update']

# List of known malicious TLDs often used by phishing sites
suspicious_tlds = ['.top', '.xyz', '.club', '.win', '.space']

def is_suspicious_url(url):
    """
    Function to check if the URL contains suspicious patterns.
    Returns True if URL is suspected of being a phishing attempt.
    """
    # Check if the URL contains any phishing keywords
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True
    return False

def check_ssl(url):
    """
    Function to check if a website uses HTTPS (SSL).
    Phishing websites often use HTTP instead of HTTPS.
    """
    if not url.startswith('https://'):
        return False
    return True

def check_domain(url):
    """
    Check if the domain is suspicious based on TLD.
    Some TLDs are more commonly used by phishing websites.
    """
    # Extract domain and TLD from URL
    ext = tldextract.extract(url)
    if ext.suffix in suspicious_tlds:
        return False
    return True

def get_http_status(url):
    """
    Check the HTTP status code of the website.
    Phishing sites may give error codes or return unusual responses.
    """
    try:
        response = requests.get(url, timeout=10)
        return response.status_code
    except requests.exceptions.RequestException:
        return None

def detect_phishing(url):
    """
    Main function to detect phishing based on different checks.
    """
    print(f"Checking URL: {url}")

    # Check if the URL contains suspicious keywords
    if is_suspicious_url(url):
        print("Suspicious keywords found in the URL.")
        return True

    # Check if the website uses SSL (HTTPS)
    if not check_ssl(url):
        print("Website does not use HTTPS.")
        return True

    # Check if the domain uses a suspicious TLD
    if not check_domain(url):
        print("Suspicious TLD found in the URL.")
        return True

    # Check the HTTP status code
    status_code = get_http_status(url)
    if status_code in [404, 500, None]:  # Common error codes or request failures
        print(f"Website returned an error (Status code: {status_code}).")
        return True

    # If all checks pass, the URL is not flagged as phishing
    print("URL looks clean.")
    return False


# Test URLs
test_urls = [
    'http://example.com/login',  # Normal URL, should raise suspicion
    'https://secure-bank-login.xyz',  # Phishing attempt with suspicious TLD
    'http://example.com',  # Non-HTTPS, could be suspicious
    'https://banking-update.top',  # Phishing attempt with suspicious TLD and URL pattern
    'https://example.com',  # Normal, clean URL
]

# Run phishing detection on test URLs
for url in test_urls:
    result = detect_phishing(url)
    print(f"URL '{url}' is phishing: {result}\n")

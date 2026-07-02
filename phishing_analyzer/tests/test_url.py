import pytest
from phishing_analyzer.detectors.url import URLDetector

@pytest.fixture
def url_detector():
    shorteners = ["bit.ly", "tinyurl.com"]
    suspicious_tlds = ["xyz", "top", "tk"]
    return URLDetector(shorteners, suspicious_tlds)

def test_url_http_detection(url_detector):
    # Insecure HTTP link should trigger
    subject = "Verify account"
    body = "Click here: http://secure-bank.com/login"
    
    matches = url_detector.detect(subject, body)
    assert len(matches) == 1
    assert matches[0].matched_text == "http://secure-bank.com/login"
    assert matches[0].pattern == "http://"

def test_url_ip_detection(url_detector):
    # IP address hosts should trigger
    subject = "Warning"
    body = "Access server: http://192.168.1.100/index"
    
    matches = url_detector.detect(subject, body)
    # Triggers: 1. http:// (insecure), 2. IP address host
    assert len(matches) == 2
    patterns = [m.pattern for m in matches]
    assert "http://" in patterns
    assert "IP address host" in patterns

def test_url_shortener_detection(url_detector):
    # URL shorteners should trigger
    subject = "Reward"
    body = "Claim it: https://bit.ly/3xyz789"
    
    matches = url_detector.detect(subject, body)
    assert len(matches) == 1
    assert matches[0].pattern == "bit.ly"

def test_url_suspicious_tld(url_detector):
    # Suspicious TLD should trigger
    subject = "Alert"
    body = "Go to: https://login.secure-site.xyz/update"
    
    matches = url_detector.detect(subject, body)
    assert len(matches) == 1
    assert matches[0].pattern == ".xyz"

def test_url_subdomain_spoofing(url_detector):
    # Subdomain spoofing with brand keyword should trigger
    subject = "PayPal Alert"
    body = "Update here: https://paypal.com.account-update.net/login"
    
    matches = url_detector.detect(subject, body)
    assert len(matches) == 1
    assert matches[0].pattern == "paypal"

def test_url_legitimate(url_detector):
    # Normal HTTPS URL should not trigger any rules
    subject = "GitHub advisory"
    body = "Check https://github.com/security-advisories for details."
    
    matches = url_detector.detect(subject, body)
    assert len(matches) == 0

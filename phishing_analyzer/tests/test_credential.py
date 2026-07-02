import pytest
from phishing_analyzer.detectors.credential import CredentialDetector

@pytest.fixture
def credential_detector():
    keywords = ["password", "otp", "pin", "bank account"]
    return CredentialDetector(keywords)

def test_credential_detection_positive(credential_detector):
    subject = "Reset your password"
    body = "Please enter your current password and bank account details."
    
    matches = credential_detector.detect(subject, body)
    assert len(matches) == 3
    matched_patterns = [m.pattern for m in matches]
    assert "password" in matched_patterns
    assert "bank account" in matched_patterns
    assert all(m.category == "sensitive_request" for m in matches)

def test_credential_detection_negative(credential_detector):
    subject = "Report submission"
    body = "The financial reports are ready for review."
    
    matches = credential_detector.detect(subject, body)
    assert len(matches) == 0

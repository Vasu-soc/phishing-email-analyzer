import pytest
from phishing_analyzer.detectors.greeting import GreetingDetector

@pytest.fixture
def greeting_detector():
    keywords = ["dear customer", "dear user", "valued customer"]
    return GreetingDetector(keywords)

def test_greeting_detection_positive(greeting_detector):
    subject = "Account notification"
    body = "Dear Customer,\nWe have updated our terms."
    
    matches = greeting_detector.detect(subject, body)
    assert len(matches) == 1
    assert matches[0].matched_text.lower() == "dear customer"
    assert matches[0].category == "generic_greeting"

def test_greeting_detection_negative(greeting_detector):
    subject = "Hello Sarah"
    body = "Hi Sarah, can you review this document?"
    
    matches = greeting_detector.detect(subject, body)
    assert len(matches) == 0

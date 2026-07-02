import pytest
from phishing_analyzer.detectors.social_engineering import SocialEngineeringDetector

@pytest.fixture
def social_engineering_detector():
    keywords = ["click here", "claim your reward", "won"]
    return SocialEngineeringDetector(keywords)

def test_social_engineering_detection_positive(social_engineering_detector):
    subject = "You won a prize!"
    body = "Click here to claim your reward now."
    
    matches = social_engineering_detector.detect(subject, body)
    assert len(matches) == 3
    matched_patterns = [m.pattern for m in matches]
    assert "won" in matched_patterns
    assert "click here" in matched_patterns
    assert "claim your reward" in matched_patterns

def test_social_engineering_detection_negative(social_engineering_detector):
    subject = "Work updates"
    body = "We have completed the migration of the database."
    
    matches = social_engineering_detector.detect(subject, body)
    assert len(matches) == 0

import pytest
from phishing_analyzer.detectors.urgency import UrgencyDetector

@pytest.fixture
def urgency_detector():
    keywords = ["urgent", "immediate action", "action required", "suspended"]
    return UrgencyDetector(keywords)

def test_urgency_detection_positive(urgency_detector):
    subject = "Urgent: Please update details"
    body = "Your account is suspended due to billing issues. Immediate action is required."
    
    matches = urgency_detector.detect(subject, body)
    
    # We expect 3 matches: "urgent" (in subject), "suspended" (in body), "immediate action" (in body)
    assert len(matches) == 3
    
    categories = [m.category for m in matches]
    assert all(c == "urgency" for c in categories)
    
    locations = [m.location for m in matches]
    assert "subject" in locations
    assert "body" in locations

def test_urgency_detection_negative(urgency_detector):
    subject = "Weekly meeting schedule"
    body = "Hi team, please find the schedule for our next meeting on Monday."
    
    matches = urgency_detector.detect(subject, body)
    assert len(matches) == 0

def test_urgency_word_boundaries(urgency_detector):
    # Tests that we don't match sub-words like "detergent"
    subject = "New detergent arrival"
    body = "The package is suspended in the air." # "suspended" should match, but "detergent" should not trigger "urgent"
    
    matches = urgency_detector.detect(subject, body)
    assert len(matches) == 1
    assert matches[0].matched_text.lower() == "suspended"

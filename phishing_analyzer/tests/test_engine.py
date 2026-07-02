import pytest
from phishing_analyzer.config import Config, WeightConfig, ThresholdConfig, DetectorConfig
from phishing_analyzer.scoring.engine import ScoringEngine

@pytest.fixture
def mock_config():
    return Config(
        weights=WeightConfig(
            urgency=10,
            suspicious_url=20,
            generic_greeting=5,
            sensitive_request=20,
            social_engineering=15
        ),
        thresholds=ThresholdConfig(
            low=15,
            medium=35,
            high=60,
            very_high=80
        ),
        detectors=DetectorConfig(
            urgency_keywords=["urgent", "suspended"],
            greeting_keywords=["dear customer"],
            sensitive_keywords=["password", "bank account"],
            social_engineering_keywords=["click here"],
            url_shorteners=["bit.ly"],
            url_suspicious_tlds=["xyz"]
        )
    )

def test_scoring_safe_email(mock_config):
    engine = ScoringEngine(mock_config)
    subject = "Hello Sarah"
    body = "Let's meet tomorrow at 10 AM to discuss details."
    
    result = engine.analyze(subject, body)
    
    assert result.final_score == 0
    assert result.risk_level == "Safe"
    assert len(result.matches) == 0

def test_scoring_medium_risk_email(mock_config):
    engine = ScoringEngine(mock_config)
    # This email triggers: generic greeting (5) and click here (15) = 20 raw score.
    # No subject triggers, so final score should be 20.
    # Risk level threshold: low is 15, medium is 35, so 20 is Low (above low threshold).
    subject = "Important update"
    body = "Dear Customer, please click here to read details."
    
    result = engine.analyze(subject, body)
    
    assert result.final_score == 20
    assert result.risk_level == "Low"
    assert len(result.matches) == 2

def test_scoring_high_risk_email(mock_config):
    engine = ScoringEngine(mock_config)
    # Subject: urgent (urgency keyword) -> triggers urgency match (10) in subject
    # Body: suspended (urgency keyword -> 10 + 3.0 = 13.0 urgency total capped at 15.0)
    # Body: bit.ly url (shortener -> 20)
    # Body: password request (sensitive -> 20)
    # Subject-line match flat bonus: +5
    # Total raw score: 13.0 (urgency) + 20.0 (url) + 20.0 (sensitive) + 5.0 (subject bonus) = 58.0.
    # Capped score: 58.
    # Risk level threshold: high is 60, medium is 35, so 58 is Medium.
    subject = "Urgent: Action required"
    body = "Your account is suspended. Reset your password here: https://bit.ly/login"
    
    result = engine.analyze(subject, body)
    
    assert result.final_score == 58
    assert result.risk_level == "Medium"

def test_scoring_very_high_risk_email(mock_config):
    engine = ScoringEngine(mock_config)
    # Triggers all categories. Score should be very high.
    # Subject: urgent (urgency: 10)
    # Body: dear customer (greeting: 5), click here (social: 15), password (sensitive: 20), http://site.xyz (url: 20 + http: 20 + xyz TLD: 20 -> capped at 20*1.5 = 30)
    # Subject bonus: +5
    # Total raw score should easily exceed 80.
    subject = "Urgent account update"
    body = "Dear Customer,\nYour account is suspended. Click here http://bank-verify.xyz to verify your password."
    
    result = engine.analyze(subject, body)
    
    assert result.final_score >= 80
    assert result.risk_level == "Very High"

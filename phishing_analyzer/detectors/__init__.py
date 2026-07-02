from dataclasses import dataclass
from typing import List, Optional

@dataclass
class DetectionMatch:
    category: str  # urgency, suspicious_url, generic_greeting, sensitive_request, social_engineering
    matched_text: str  # The exact substring that triggered the rule
    pattern: str  # The keyword or regex pattern that was matched
    explanation: str  # Detailed explanation of why it is suspicious
    location: str  # "subject" or "body"
    start_index: int  # Start position in the text
    end_index: int  # End position in the text

class BaseDetector:
    """
    Base class for all phishing indicator detectors.
    """
    def __init__(self, category: str):
        self.category = category

    def detect(self, subject: str, body: str) -> List[DetectionMatch]:
        """
        Analyze the email subject and body. Returns a list of DetectionMatch objects.
        """
        raise NotImplementedError("Subclasses must implement detect()")

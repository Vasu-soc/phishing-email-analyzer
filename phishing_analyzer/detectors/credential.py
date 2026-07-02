import re
from typing import List
from phishing_analyzer.detectors import BaseDetector, DetectionMatch

class CredentialDetector(BaseDetector):
    """
    Detects requests for sensitive/credential information like passwords, OTPs, PINs, and financial data.
    """
    def __init__(self, keywords: List[str]):
        super().__init__(category="sensitive_request")
        self.keywords = keywords

    def detect(self, subject: str, body: str) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        
        matches.extend(self._find_keywords(subject, "subject"))
        matches.extend(self._find_keywords(body, "body"))
        
        return matches

    def _find_keywords(self, text: str, location: str) -> List[DetectionMatch]:
        if not text:
            return []
            
        matches: List[DetectionMatch] = []
        
        for keyword in self.keywords:
            escaped_kw = re.escape(keyword)
            # Use word boundaries, case-insensitive
            pattern = rf"\b{escaped_kw}\b"
            
            for match in re.finditer(pattern, text, re.IGNORECASE):
                start, end = match.span()
                matched_text = match.group(0)
                explanation = (
                    f"Sensitive credentials request ('{matched_text}') detected in the {location}. "
                    "Legitimate organizations rarely request passwords, OTPs, PINs, or direct banking info via email."
                )
                matches.append(DetectionMatch(
                    category=self.category,
                    matched_text=matched_text,
                    pattern=keyword,
                    explanation=explanation,
                    location=location,
                    start_index=start,
                    end_index=end
                ))
                
        return matches

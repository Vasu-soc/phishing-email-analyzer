import re
from typing import List
from phishing_analyzer.detectors import BaseDetector, DetectionMatch

class UrgencyDetector(BaseDetector):
    """
    Detects urgent, coercive, or threatening language in email subject and body.
    """
    def __init__(self, keywords: List[str]):
        super().__init__(category="urgency")
        self.keywords = keywords

    def detect(self, subject: str, body: str) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        
        # Check subject
        matches.extend(self._find_keywords(subject, "subject"))
        
        # Check body
        matches.extend(self._find_keywords(body, "body"))
        
        return matches

    def _find_keywords(self, text: str, location: str) -> List[DetectionMatch]:
        if not text:
            return []
            
        matches: List[DetectionMatch] = []
        
        # Search for each keyword as a word boundary match to avoid false positives (e.g. "urgent" in "detergent")
        for keyword in self.keywords:
            # Escape keyword for regex safety
            escaped_kw = re.escape(keyword)
            # Match whole phrase/word case-insensitively
            pattern = rf"\b{escaped_kw}\b"
            
            for match in re.finditer(pattern, text, re.IGNORECASE):
                start, end = match.span()
                matched_text = match.group(0)
                explanation = (
                    f"Urgent or coercive language ('{matched_text}') detected in the {location}. "
                    "Phishers create a false sense of urgency to force quick, unthinking actions."
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

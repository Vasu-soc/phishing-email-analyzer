import re
from typing import List
from phishing_analyzer.detectors import BaseDetector, DetectionMatch

class SocialEngineeringDetector(BaseDetector):
    """
    Detects common social engineering phrases such as 'click here', 'claim your reward', etc.
    """
    def __init__(self, keywords: List[str]):
        super().__init__(category="social_engineering")
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
            # Use word boundaries if possible, but allow phrase matches (phrases can contain spaces)
            pattern = rf"\b{escaped_kw}\b"
            
            for match in re.finditer(pattern, text, re.IGNORECASE):
                start, end = match.span()
                matched_text = match.group(0)
                explanation = (
                    f"Social engineering phrase ('{matched_text}') detected in the {location}. "
                    "Phrases prompting user action or offering rewards are signature techniques to induce compliance."
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

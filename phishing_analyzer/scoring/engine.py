from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any
from phishing_analyzer.config import Config
from phishing_analyzer.detectors import DetectionMatch, BaseDetector
from phishing_analyzer.detectors.urgency import UrgencyDetector
from phishing_analyzer.detectors.url import URLDetector
from phishing_analyzer.detectors.greeting import GreetingDetector
from phishing_analyzer.detectors.credential import CredentialDetector
from phishing_analyzer.detectors.social_engineering import SocialEngineeringDetector

@dataclass
class AnalysisResult:
    subject: str
    body: str
    matches: List[DetectionMatch]
    category_matches: Dict[str, List[DetectionMatch]]
    category_scores: Dict[str, float]
    raw_score: float
    final_score: int
    risk_level: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the analysis result to a dictionary representation (for JSON report).
        """
        return {
            "timestamp": self.timestamp,
            "subject": self.subject,
            "body": self.body,
            "risk_level": self.risk_level,
            "final_score": self.final_score,
            "raw_score": self.raw_score,
            "category_scores": self.category_scores,
            "matches_count": len(self.matches),
            "matches": [
                {
                    "category": m.category,
                    "matched_text": m.matched_text,
                    "pattern": m.pattern,
                    "explanation": m.explanation,
                    "location": m.location,
                    "start_index": m.start_index,
                    "end_index": m.end_index
                } for m in self.matches
            ]
        }


class ScoringEngine:
    """
    Orchestrates the running of detectors and calculates the weighted phishing risk score.
    """
    def __init__(self, config: Config):
        self.config = config
        self.detectors: List[BaseDetector] = [
            UrgencyDetector(config.detectors.urgency_keywords),
            URLDetector(config.detectors.url_shorteners, config.detectors.url_suspicious_tlds),
            GreetingDetector(config.detectors.greeting_keywords),
            CredentialDetector(config.detectors.sensitive_keywords),
            SocialEngineeringDetector(config.detectors.social_engineering_keywords)
        ]

    def analyze(self, subject: str, body: str) -> AnalysisResult:
        """
        Executes all registered detectors and runs the scoring engine.
        """
        all_matches: List[DetectionMatch] = []
        category_matches: Dict[str, List[DetectionMatch]] = {
            "urgency": [],
            "suspicious_url": [],
            "generic_greeting": [],
            "sensitive_request": [],
            "social_engineering": []
        }

        # Run all detectors
        for detector in self.detectors:
            matches = detector.detect(subject, body)
            all_matches.extend(matches)
            for m in matches:
                if m.category in category_matches:
                    category_matches[m.category].append(m)

        # Calculate category scores
        category_scores: Dict[str, float] = {}
        total_raw_score = 0.0

        # Weights configuration mapping
        weights_map = {
            "urgency": self.config.weights.urgency,
            "suspicious_url": self.config.weights.suspicious_url,
            "generic_greeting": self.config.weights.generic_greeting,
            "sensitive_request": self.config.weights.sensitive_request,
            "social_engineering": self.config.weights.social_engineering
        }

        for category, matches in category_matches.items():
            weight = weights_map.get(category, 0)
            if not matches:
                category_scores[category] = 0.0
                continue

            # Scoring algorithm:
            # - First match gives 100% of category weight
            # - Each additional match in the category adds a small penalty/bonus (+3 points)
            # - Capped at 1.5x the category weight
            num_matches = len(matches)
            cat_score = weight + (num_matches - 1) * 3.0
            cat_score = min(cat_score, weight * 1.5)
            
            category_scores[category] = cat_score
            total_raw_score += cat_score

        # Add flat bonus if subject line itself contains flags (as it indicates targeted phishing lure)
        subject_has_matches = any(m.location == "subject" for m in all_matches)
        if subject_has_matches:
            total_raw_score += 5.0

        # Normalize/cap score to range 0-100
        final_score = int(round(min(100.0, total_raw_score)))
        
        # If there are matches but score is 0 due to custom weight configuration, make it at least 1
        if all_matches and final_score == 0:
            final_score = 1

        # Determine risk level based on thresholds
        risk_level = self._determine_risk_level(final_score)

        return AnalysisResult(
            subject=subject,
            body=body,
            matches=all_matches,
            category_matches=category_matches,
            category_scores=category_scores,
            raw_score=total_raw_score,
            final_score=final_score,
            risk_level=risk_level
        )

    def _determine_risk_level(self, score: int) -> str:
        t = self.config.thresholds
        
        if score == 0:
            return "Safe"
        elif score < t.medium:
            return "Low"
        elif score < t.high:
            return "Medium"
        elif score < t.very_high:
            return "High"
        else:
            return "Very High"

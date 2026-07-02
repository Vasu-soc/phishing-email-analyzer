import os
from dataclasses import dataclass, field
from typing import List, Dict, Any
import yaml

@dataclass
class WeightConfig:
    urgency: int = 15
    suspicious_url: int = 25
    generic_greeting: int = 10
    sensitive_request: int = 25
    social_engineering: int = 25

@dataclass
class DetectorConfig:
    urgency_keywords: List[str] = field(default_factory=list)
    greeting_keywords: List[str] = field(default_factory=list)
    sensitive_keywords: List[str] = field(default_factory=list)
    social_engineering_keywords: List[str] = field(default_factory=list)
    url_shorteners: List[str] = field(default_factory=list)
    url_suspicious_tlds: List[str] = field(default_factory=list)

@dataclass
class ThresholdConfig:
    low: int = 15
    medium: int = 35
    high: int = 60
    very_high: int = 80

@dataclass
class Config:
    weights: WeightConfig = field(default_factory=WeightConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    detectors: DetectorConfig = field(default_factory=DetectorConfig)


def load_config(config_path: str = None) -> Config:
    """
    Loads configuration from a YAML file. If path is not provided, loads the default config.
    Falls back to default values in case of error.
    """
    # Determine path to default config
    current_dir = os.path.dirname(os.path.abspath(__file__))
    default_path = os.path.join(current_dir, "default_config.yaml")

    config_data: Dict[str, Any] = {}

    # Helper function to read a yaml file
    def read_yaml(path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                return content if isinstance(content, dict) else {}
        except Exception:
            # Safe fallback if file is malformed or inaccessible
            return {}

    # Always load default configuration first as base
    default_data = read_yaml(default_path)
    
    # If custom config provided, load and override
    custom_data = {}
    if config_path:
        custom_data = read_yaml(config_path)

    # Merge custom data over default data
    def deep_merge(dict1: dict, dict2: dict) -> dict:
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    config_data = deep_merge(default_data, custom_data) if custom_data else default_data

    # Parse Weights
    w_data = config_data.get("weights", {})
    weights = WeightConfig(
        urgency=w_data.get("urgency", 15),
        suspicious_url=w_data.get("suspicious_url", 25),
        generic_greeting=w_data.get("generic_greeting", 10),
        sensitive_request=w_data.get("sensitive_request", 25),
        social_engineering=w_data.get("social_engineering", 25)
    )

    # Parse Thresholds
    t_data = config_data.get("thresholds", {})
    thresholds = ThresholdConfig(
        low=t_data.get("low", 15),
        medium=t_data.get("medium", 35),
        high=t_data.get("high", 60),
        very_high=t_data.get("very_high", 80)
    )

    # Parse Detectors
    d_data = config_data.get("detectors", {})
    detectors = DetectorConfig(
        urgency_keywords=[str(k).lower() for k in d_data.get("urgency", {}).get("keywords", [])],
        greeting_keywords=[str(k).lower() for k in d_data.get("greeting", {}).get("keywords", [])],
        sensitive_keywords=[str(k).lower() for k in d_data.get("sensitive_request", {}).get("keywords", [])],
        social_engineering_keywords=[str(k).lower() for k in d_data.get("social_engineering", {}).get("keywords", [])],
        url_shorteners=[str(s).lower() for s in d_data.get("url", {}).get("shorteners", [])],
        url_suspicious_tlds=[str(t).lower() for t in d_data.get("url", {}).get("suspicious_tlds", [])]
    )

    # Fallbacks if default YAML loading failed completely
    if not detectors.urgency_keywords:
        # Hardcoded fallback list in case yaml file is missing or empty
        detectors.urgency_keywords = ["urgent", "immediate action", "action required", "suspended"]
    if not detectors.greeting_keywords:
        detectors.greeting_keywords = ["dear customer", "dear user", "dear client"]
    if not detectors.sensitive_keywords:
        detectors.sensitive_keywords = ["password", "otp", "pin", "bank account"]
    if not detectors.social_engineering_keywords:
        detectors.social_engineering_keywords = ["click here", "claim your reward"]
    if not detectors.url_shorteners:
        detectors.url_shorteners = ["bit.ly", "tinyurl.com"]
    if not detectors.url_suspicious_tlds:
        detectors.url_suspicious_tlds = ["xyz", "top", "tk"]

    return Config(weights=weights, thresholds=thresholds, detectors=detectors)

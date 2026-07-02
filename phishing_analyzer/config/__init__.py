"""
Configuration modules for the Phishing Email Analyzer.
"""
from phishing_analyzer.config.loader import load_config, Config, DetectorConfig, WeightConfig, ThresholdConfig

__all__ = ["load_config", "Config", "DetectorConfig", "WeightConfig", "ThresholdConfig"]

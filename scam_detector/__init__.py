"""Scam Detection Agent - AI-powered scam pattern detection for forum posts."""

from .models import ScamPattern, Post, DetectionResult, RiskLevel, PatternMatch
from .client import OpenAIClient, ChatMessage, ClientConfig
from .detector import ScamDetector
from .patterns import (
    get_common_patterns,
    get_financial_patterns,
    get_marketplace_patterns,
    get_employment_patterns,
    get_tech_patterns,
    ADVANCE_FEE_SCAM,
    CRYPTO_PUMP_AND_DUMP,
    FAKE_INVESTMENT,
    FAKE_BUYER,
    FAKE_SELLER,
    ROMANCE_SCAM,
    FAKE_JOB,
    MONEY_MULE,
    TECH_SUPPORT_SCAM,
    PHISHING,
)

__all__ = [
    # Core classes
    "ScamPattern",
    "Post",
    "DetectionResult",
    "PatternMatch",
    "RiskLevel",
    "OpenAIClient",
    "ChatMessage",
    "ClientConfig",
    "ScamDetector",
    # Pattern getters
    "get_common_patterns",
    "get_financial_patterns",
    "get_marketplace_patterns",
    "get_employment_patterns",
    "get_tech_patterns",
    # Individual patterns
    "ADVANCE_FEE_SCAM",
    "CRYPTO_PUMP_AND_DUMP",
    "FAKE_INVESTMENT",
    "FAKE_BUYER",
    "FAKE_SELLER",
    "ROMANCE_SCAM",
    "FAKE_JOB",
    "MONEY_MULE",
    "TECH_SUPPORT_SCAM",
    "PHISHING",
]

__version__ = "0.1.0"

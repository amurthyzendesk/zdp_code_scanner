"""
Models Module
=============

Data structures for the security audit framework.
"""

from .chain_of_thought import (
    ChainOfThought,
    DetectionReasoning,
    RiskAnalysis,
    AttackScenario,
    ContextAnalysis,
    FalsePositiveAssessment,
    ConfidenceRationale,
    AlternativeExplanations,
    RemediationReasoning,
    ConfidenceLevel,
    create_example_cot
)

__all__ = [
    'ChainOfThought',
    'DetectionReasoning',
    'RiskAnalysis',
    'AttackScenario',
    'ContextAnalysis',
    'FalsePositiveAssessment',
    'ConfidenceRationale',
    'AlternativeExplanations',
    'RemediationReasoning',
    'ConfidenceLevel',
    'create_example_cot'
]

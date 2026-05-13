#!/usr/bin/env python3
"""
Chain of Thought (CoT) Model
=============================

Captures reasoning for security findings to provide explainability.

For HIGH and CRITICAL findings, we capture:
- Detection reasoning: Why was this detected as a security issue?
- Risk analysis: What makes this dangerous?
- Attack scenario: How could an attacker exploit this?
- Context analysis: What surrounding code is relevant?
- False positive assessment: Could this be a false positive? Why/why not?
- Confidence rationale: Why is our confidence level HIGH/MEDIUM/LOW?
- Alternative explanations: Are there legitimate reasons for this code?
- Remediation reasoning: Why is our recommended fix the best approach?

This structured reasoning helps security teams:
1. Understand the finding without deep code analysis
2. Prioritize remediation efforts
3. Learn security patterns
4. Provide context to developers
5. Build institutional security knowledge
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence in finding accuracy."""
    HIGH = "HIGH"       # 90-100% confidence (multiple signals, clear evidence)
    MEDIUM = "MEDIUM"   # 70-89% confidence (some ambiguity, needs review)
    LOW = "LOW"         # 50-69% confidence (possible false positive)


@dataclass
class DetectionReasoning:
    """
    Why was this issue detected?

    Explains the detection logic and evidence that triggered the finding.
    """
    pattern_matched: str  # What pattern/rule triggered this
    evidence_summary: str  # Brief summary of the evidence
    detection_method: str  # How was it detected (regex, AST, semantic analysis, etc.)
    signals_observed: List[str]  # List of specific signals (e.g., ["SQL concatenation", "user input"])

    # Optional: Agent-specific detection details
    agent_name: Optional[str] = None
    check_name: Optional[str] = None


@dataclass
class RiskAnalysis:
    """
    What makes this dangerous?

    Explains the security impact and potential consequences.
    """
    severity_reasoning: str  # Why CRITICAL/HIGH vs MEDIUM/LOW
    impact_description: str  # What could go wrong
    affected_assets: List[str]  # What's at risk (data, systems, users)
    attack_surface: str  # How exposed is this vulnerability

    # Business impact context
    data_sensitivity: Optional[str] = None  # e.g., "PII", "Financial", "Credentials"
    compliance_impact: Optional[List[str]] = None  # e.g., ["GDPR", "PCI DSS"]


@dataclass
class AttackScenario:
    """
    How could an attacker exploit this?

    Provides concrete attack scenarios to help understand exploitability.
    """
    attack_vector: str  # How would an attacker trigger this
    attack_steps: List[str]  # Step-by-step exploitation
    required_access: str  # What access level does attacker need
    exploitability_rating: str  # Easy, Medium, Hard, Very Hard

    # Real-world context
    similar_cves: Optional[List[str]] = None  # Related CVEs if applicable
    exploit_examples: Optional[str] = None  # Example exploit code/technique


@dataclass
class ContextAnalysis:
    """
    What surrounding code is relevant?

    Provides context about where this occurs and what it interacts with.
    """
    function_purpose: Optional[str] = None  # What does the containing function do
    data_flow: Optional[str] = None  # Where does data come from and go to
    surrounding_controls: List[str] = field(default_factory=list)  # Existing security controls
    missing_controls: List[str] = field(default_factory=list)  # What controls are absent

    # Code location context
    file_purpose: Optional[str] = None  # What is this file responsible for
    framework_context: Optional[str] = None  # Framework-specific details


@dataclass
class FalsePositiveAssessment:
    """
    Could this be a false positive?

    Honest assessment of false positive likelihood and reasoning.
    """
    is_likely_false_positive: bool
    reasoning: str  # Why we think it is/isn't a false positive
    ambiguity_factors: List[str]  # What makes this unclear
    validation_needed: Optional[str] = None  # What would confirm true positive

    # Confidence modifiers
    confidence_boosters: List[str] = field(default_factory=list)  # Evidence this is real
    confidence_detractors: List[str] = field(default_factory=list)  # Evidence this might be FP


@dataclass
class ConfidenceRationale:
    """
    Why is our confidence level HIGH/MEDIUM/LOW?

    Explains the factors contributing to confidence assessment.
    """
    confidence_level: ConfidenceLevel
    primary_factors: List[str]  # Main reasons for confidence level

    # Evidence strength
    strong_evidence: List[str] = field(default_factory=list)  # Clear indicators
    weak_evidence: List[str] = field(default_factory=list)  # Ambiguous indicators

    # Consensus
    agent_agreement: Optional[int] = None  # How many agents agreed (1-3)
    agreement_details: Optional[str] = None  # What did agreeing agents see


@dataclass
class AlternativeExplanations:
    """
    Are there legitimate reasons for this code?

    Consider valid use cases that might look like vulnerabilities.
    """
    possible_legitimate_uses: List[str]
    counterarguments: List[str]  # Why these alternatives don't apply here
    requires_human_judgment: bool  # Does this need human review


@dataclass
class RemediationReasoning:
    """
    Why is our recommended fix the best approach?

    Explains the remediation strategy and alternatives.
    """
    recommended_fix: str  # Primary recommendation
    fix_rationale: str  # Why this is the best approach

    # Alternative approaches
    alternative_fixes: List[str] = field(default_factory=list)
    tradeoffs: Optional[str] = None  # Pros/cons of different approaches

    # Implementation guidance
    implementation_complexity: str = "Medium"  # Easy, Medium, Hard
    breaking_changes: bool = False
    testing_guidance: Optional[str] = None


@dataclass
class ChainOfThought:
    """
    Complete Chain of Thought for a security finding.

    This is the master structure that ties all reasoning together.
    Only populated for HIGH and CRITICAL findings (performance optimization).
    """

    # Core reasoning components (always present for HIGH/CRITICAL)
    detection: DetectionReasoning
    risk: RiskAnalysis
    attack: AttackScenario
    confidence: ConfidenceRationale
    remediation: RemediationReasoning

    # Optional components (populated when relevant)
    context: Optional[ContextAnalysis] = None
    false_positive: Optional[FalsePositiveAssessment] = None
    alternatives: Optional[AlternativeExplanations] = None

    # Metadata
    generated_by_agent: str = "unknown"
    generated_at: Optional[str] = None  # ISO timestamp

    def to_dict(self) -> Dict:
        """
        Convert CoT to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the Chain of Thought
        """
        def _dataclass_to_dict(obj):
            """Recursively convert dataclass to dict."""
            if obj is None:
                return None
            elif isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, list):
                return [_dataclass_to_dict(item) for item in obj]
            elif hasattr(obj, '__dataclass_fields__'):
                return {
                    key: _dataclass_to_dict(value)
                    for key, value in obj.__dict__.items()
                    if value is not None
                }
            else:
                return obj

        return _dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'ChainOfThought':
        """
        Create ChainOfThought from dictionary.

        Args:
            data: Dictionary representation

        Returns:
            ChainOfThought instance
        """
        # This is a simplified version - full implementation would handle nested dataclasses
        # For now, we'll use this for basic serialization
        return cls(**data)

    def get_summary(self) -> str:
        """
        Get a concise summary of the Chain of Thought.

        Returns:
            Human-readable summary string
        """
        lines = []
        lines.append("CHAIN OF THOUGHT REASONING")
        lines.append("=" * 60)
        lines.append("")

        # Detection
        lines.append(f"🔍 Detection: {self.detection.pattern_matched}")
        lines.append(f"   Method: {self.detection.detection_method}")
        lines.append(f"   Signals: {', '.join(self.detection.signals_observed)}")
        lines.append("")

        # Risk
        lines.append(f"⚠️  Risk: {self.risk.severity_reasoning}")
        lines.append(f"   Impact: {self.risk.impact_description}")
        lines.append(f"   Assets at risk: {', '.join(self.risk.affected_assets)}")
        lines.append("")

        # Attack
        lines.append(f"💥 Attack Vector: {self.attack.attack_vector}")
        lines.append(f"   Exploitability: {self.attack.exploitability_rating}")
        lines.append(f"   Required access: {self.attack.required_access}")
        lines.append("")

        # Confidence
        lines.append(f"📊 Confidence: {self.confidence.confidence_level.value}")
        lines.append(f"   Rationale: {', '.join(self.confidence.primary_factors)}")
        if self.confidence.agent_agreement:
            lines.append(f"   Agent consensus: {self.confidence.agent_agreement}/3 agents agree")
        lines.append("")

        # Remediation
        lines.append(f"🔧 Recommended Fix: {self.remediation.recommended_fix}")
        lines.append(f"   Rationale: {self.remediation.fix_rationale}")
        lines.append(f"   Complexity: {self.remediation.implementation_complexity}")
        lines.append("")

        # False positive assessment (if present)
        if self.false_positive:
            fp_status = "likely" if self.false_positive.is_likely_false_positive else "unlikely"
            lines.append(f"❓ False Positive: {fp_status}")
            lines.append(f"   Reasoning: {self.false_positive.reasoning}")
            lines.append("")

        return "\n".join(lines)


# Helper function to create a basic CoT for testing
def create_example_cot() -> ChainOfThought:
    """
    Create an example Chain of Thought for demonstration/testing.

    Returns:
        Example ChainOfThought instance
    """
    return ChainOfThought(
        detection=DetectionReasoning(
            pattern_matched="SQL Injection via string concatenation",
            evidence_summary="User input concatenated directly into SQL query",
            detection_method="AST analysis + pattern matching",
            signals_observed=["String concatenation with user input", "execute() call", "No parameterization"],
            agent_name="SecurityReviewerAgent",
            check_name="check_sql_injection"
        ),
        risk=RiskAnalysis(
            severity_reasoning="Direct SQL injection with no input validation or parameterization",
            impact_description="Attacker can read, modify, or delete database records; potential data breach",
            affected_assets=["User database", "PII", "Authentication data"],
            attack_surface="Publicly accessible API endpoint",
            data_sensitivity="PII + Financial",
            compliance_impact=["GDPR", "PCI DSS", "SOC 2"]
        ),
        attack=AttackScenario(
            attack_vector="HTTP POST request with SQL payload in username parameter",
            attack_steps=[
                "Send POST request to /api/login",
                "Include SQL payload: ' OR '1'='1' -- ",
                "Bypass authentication",
                "Access unauthorized data"
            ],
            required_access="Public network access (no authentication required)",
            exploitability_rating="Easy",
            similar_cves=["CVE-2019-12345", "CVE-2020-67890"]
        ),
        confidence=ConfidenceRationale(
            confidence_level=ConfidenceLevel.HIGH,
            primary_factors=[
                "Clear string concatenation pattern",
                "User input directly in query",
                "No parameterization present"
            ],
            strong_evidence=["Direct concatenation", "execute() with string"],
            agent_agreement=3,
            agreement_details="All 3 agents (security, privacy, permission) flagged this"
        ),
        remediation=RemediationReasoning(
            recommended_fix="Use parameterized queries (prepared statements)",
            fix_rationale="Parameterization separates SQL logic from data, preventing injection",
            alternative_fixes=[
                "Use ORM query builder",
                "Input validation + escaping (less secure)"
            ],
            tradeoffs="ORM is safest but requires more refactoring; parameterization is quick and effective",
            implementation_complexity="Easy",
            breaking_changes=False,
            testing_guidance="Test with SQL injection payloads to verify fix"
        ),
        false_positive=FalsePositiveAssessment(
            is_likely_false_positive=False,
            reasoning="Clear SQL injection pattern with no mitigating controls",
            ambiguity_factors=[],
            confidence_boosters=["Direct concatenation", "User-controlled input", "No validation"],
            confidence_detractors=[]
        ),
        context=ContextAnalysis(
            function_purpose="User authentication",
            data_flow="HTTP request → user_input → SQL query → database",
            missing_controls=["Input validation", "Parameterization", "WAF"],
            file_purpose="Authentication module",
            framework_context="Flask application using raw SQL"
        ),
        generated_by_agent="SecurityReviewerAgent",
        generated_at="2026-05-13T15:00:00Z"
    )


if __name__ == "__main__":
    # Example usage
    example = create_example_cot()
    print(example.get_summary())
    print("\nJSON representation:")
    import json
    print(json.dumps(example.to_dict(), indent=2))

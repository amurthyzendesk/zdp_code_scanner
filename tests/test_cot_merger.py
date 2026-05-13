#!/usr/bin/env python3
"""
Test CoT Merger
===============

Tests the Chain of Thought consensus merger.
"""

import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from brex_audit.models import (
    ChainOfThought,
    DetectionReasoning,
    RiskAnalysis,
    AttackScenario,
    ConfidenceRationale,
    RemediationReasoning,
    ConfidenceLevel
)
from brex_audit.consensus import CoTMerger


def test_merge_two_agents():
    """Test merging CoT from 2 agents."""
    print("Test 1: Merge CoT from 2 agents")

    # Security agent CoT
    security_cot = ChainOfThought(
        detection=DetectionReasoning(
            pattern_matched="SQL Injection",
            evidence_summary="String concatenation in query",
            detection_method="AST analysis",
            signals_observed=["String concat", "execute() call"],
            agent_name="SecurityReviewerAgent"
        ),
        risk=RiskAnalysis(
            severity_reasoning="Direct SQL injection allows data breach",
            impact_description="Unauthorized data access",
            affected_assets=["Database", "User data"],
            attack_surface="API endpoint",
            compliance_impact=["OWASP A03"]
        ),
        attack=AttackScenario(
            attack_vector="HTTP POST with SQL payload",
            attack_steps=["Send payload", "Execute query"],
            required_access="Public",
            exploitability_rating="Easy"
        ),
        confidence=ConfidenceRationale(
            confidence_level=ConfidenceLevel.HIGH,
            primary_factors=["Clear pattern"],
            strong_evidence=["Direct concat"],
            agent_agreement=1
        ),
        remediation=RemediationReasoning(
            recommended_fix="Use parameterized queries",
            fix_rationale="Separates SQL from data",
            alternative_fixes=["Use ORM"],
            implementation_complexity="Easy"
        ),
        generated_by_agent="SecurityReviewerAgent",
        generated_at=datetime.now().isoformat()
    )

    # Permission agent CoT
    permission_cot = ChainOfThought(
        detection=DetectionReasoning(
            pattern_matched="SQL Injection via string concat",
            evidence_summary="Query with user input",
            detection_method="SQL parsing",
            signals_observed=["No parameterization", "User input"],
            agent_name="PermissionReviewerAgent"
        ),
        risk=RiskAnalysis(
            severity_reasoning="Bypasses authorization checks",
            impact_description="Privilege escalation possible",
            affected_assets=["Authorization system", "All tables"],
            attack_surface="Any authenticated endpoint",
            compliance_impact=["CIS Benchmark 1.1"]
        ),
        attack=AttackScenario(
            attack_vector="Malicious SQL in parameter",
            attack_steps=["Craft payload", "Bypass WHERE", "Access other users' data"],
            required_access="Authenticated user",
            exploitability_rating="Easy"
        ),
        confidence=ConfidenceRationale(
            confidence_level=ConfidenceLevel.HIGH,
            primary_factors=["SQL pattern", "No filters"],
            strong_evidence=["String building"],
            agent_agreement=1
        ),
        remediation=RemediationReasoning(
            recommended_fix="Parameterized queries + input validation",
            fix_rationale="Prevents injection and validates input",
            alternative_fixes=["Stored procedures"],
            implementation_complexity="Easy"
        ),
        generated_by_agent="PermissionReviewerAgent",
        generated_at=datetime.now().isoformat()
    )

    # Merge
    merger = CoTMerger()
    merged = merger.merge_cots(
        [security_cot, permission_cot],
        consensus_level=2,
        agreeing_agents=["SecurityReviewerAgent", "PermissionReviewerAgent"]
    )

    # Verify
    assert merged.confidence.agent_agreement == 2
    assert "SecurityReviewerAgent" in merged.confidence.agreement_details
    assert "PermissionReviewerAgent" in merged.confidence.agreement_details

    # Should have signals from both agents
    assert len(merged.detection.signals_observed) >= 3

    # Should have assets from both
    assert len(merged.risk.affected_assets) >= 3

    # Should have compliance from both
    assert "OWASP" in str(merged.risk.compliance_impact)
    assert "CIS" in str(merged.risk.compliance_impact)

    print("   ✅ Merged 2 agents successfully")
    print(f"   ✅ Consensus level: {merged.confidence.agent_agreement}")
    print(f"   ✅ Combined signals: {len(merged.detection.signals_observed)}")
    print(f"   ✅ Combined assets: {len(merged.risk.affected_assets)}")
    print()


def test_merge_three_agents():
    """Test merging CoT from all 3 agents."""
    print("Test 2: Merge CoT from 3 agents (full consensus)")

    # Simplified CoTs for 3 agents
    cots = []
    for agent in ["SecurityReviewerAgent", "PrivacyReviewerAgent", "PermissionReviewerAgent"]:
        cot = ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=f"Issue detected by {agent}",
                evidence_summary="Evidence",
                detection_method="Pattern matching",
                signals_observed=[f"Signal from {agent}"],
                agent_name=agent
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"Risk from {agent} perspective",
                impact_description="High impact",
                affected_assets=[f"Asset {agent}"],
                attack_surface="Wide",
                compliance_impact=[f"Compliance {agent}"]
            ),
            attack=AttackScenario(
                attack_vector="Attack vector",
                attack_steps=[f"Step from {agent}"],
                required_access="Low",
                exploitability_rating="Easy"
            ),
            confidence=ConfidenceRationale(
                confidence_level=ConfidenceLevel.HIGH,
                primary_factors=[f"Factor from {agent}"],
                strong_evidence=[f"Evidence {agent}"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Fix it",
                fix_rationale=f"Rationale from {agent}",
                alternative_fixes=[f"Alt from {agent}"],
                implementation_complexity="Medium"
            ),
            generated_by_agent=agent
        )
        cots.append(cot)

    # Merge
    merger = CoTMerger()
    merged = merger.merge_cots(
        cots,
        consensus_level=3,
        agreeing_agents=["SecurityReviewerAgent", "PrivacyReviewerAgent", "PermissionReviewerAgent"]
    )

    # Verify full consensus
    assert merged.confidence.agent_agreement == 3
    assert merged.confidence.confidence_level == ConfidenceLevel.HIGH  # 3 agents = highest confidence

    # Should have contributions from all 3
    assert len(merged.detection.signals_observed) == 3
    assert len(merged.risk.affected_assets) == 3

    print("   ✅ Merged 3 agents successfully")
    print(f"   ✅ Full consensus achieved: {merged.confidence.agent_agreement} agents")
    print(f"   ✅ Confidence: {merged.confidence.confidence_level.value}")
    print()


def test_merge_preserves_details():
    """Test that merging preserves important details."""
    print("Test 3: Merge preserves important details")

    cot1 = ChainOfThought(
        detection=DetectionReasoning(
            pattern_matched="Hardcoded password",
            evidence_summary="password = 'secret123'",
            detection_method="Regex",
            signals_observed=["Plaintext password", "String assignment"],
            agent_name="SecurityReviewerAgent"
        ),
        risk=RiskAnalysis(
            severity_reasoning="Credentials exposed in code",
            impact_description="Account takeover",
            affected_assets=["Database credentials"],
            attack_surface="Source code access",
            data_sensitivity="Credentials",
            compliance_impact=["CIS 1.1", "OWASP A07"]
        ),
        attack=AttackScenario(
            attack_vector="Code access",
            attack_steps=["Read source", "Extract password", "Login"],
            required_access="Code repository",
            exploitability_rating="Medium",
            similar_cves=["CVE-2020-1234"]
        ),
        confidence=ConfidenceRationale(
            confidence_level=ConfidenceLevel.HIGH,
            primary_factors=["Clear hardcoded value"],
            strong_evidence=["String literal"],
            agent_agreement=1
        ),
        remediation=RemediationReasoning(
            recommended_fix="Use environment variables",
            fix_rationale="Separates secrets from code",
            alternative_fixes=["Use secrets manager", "Use vault"],
            tradeoffs="Env vars are simple; vault is more secure",
            implementation_complexity="Easy",
            breaking_changes=False
        ),
        generated_by_agent="SecurityReviewerAgent"
    )

    cot2 = ChainOfThought(
        detection=DetectionReasoning(
            pattern_matched="Credential exposure",
            evidence_summary="Password in source",
            detection_method="AST",
            signals_observed=["No encryption"],
            agent_name="PrivacyReviewerAgent"
        ),
        risk=RiskAnalysis(
            severity_reasoning="Privacy violation",
            impact_description="Data breach risk",
            affected_assets=["User accounts"],
            attack_surface="Repository",
            data_sensitivity="PII",
            compliance_impact=["GDPR Article 32"]
        ),
        attack=AttackScenario(
            attack_vector="Git history",
            attack_steps=["Clone repo", "Search for passwords"],
            required_access="Public or dev access",
            exploitability_rating="Easy"
        ),
        confidence=ConfidenceRationale(
            confidence_level=ConfidenceLevel.HIGH,
            primary_factors=["Visible in code"],
            strong_evidence=["Plaintext"],
            agent_agreement=1
        ),
        remediation=RemediationReasoning(
            recommended_fix="Rotate credentials and use secrets manager",
            fix_rationale="Invalidates old creds and prevents future exposure",
            alternative_fixes=["Environment variables"],
            implementation_complexity="Medium",
            breaking_changes=True
        ),
        generated_by_agent="PrivacyReviewerAgent"
    )

    # Merge
    merger = CoTMerger()
    merged = merger.merge_cots([cot1, cot2], 2, ["SecurityReviewerAgent", "PrivacyReviewerAgent"])

    # Verify preservation of details
    assert "CVE-2020-1234" in (merged.attack.similar_cves or [])
    assert "CIS" in str(merged.risk.compliance_impact)
    assert "GDPR" in str(merged.risk.compliance_impact)
    assert "OWASP" in str(merged.risk.compliance_impact)
    assert merged.remediation.tradeoffs is not None
    assert merged.remediation.breaking_changes == True  # Most conservative

    print("   ✅ CVEs preserved")
    print("   ✅ Compliance references merged")
    print("   ✅ Tradeoffs preserved")
    print("   ✅ Breaking changes flagged correctly")
    print()


def run_all_tests():
    """Run all CoT merger tests."""
    print("=" * 80)
    print("COT MERGER TEST SUITE")
    print("=" * 80)
    print()

    try:
        test_merge_two_agents()
        test_merge_three_agents()
        test_merge_preserves_details()

        print("=" * 80)
        print("✅ ALL TESTS PASSED")
        print("=" * 80)
        return True
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)

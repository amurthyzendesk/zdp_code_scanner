#!/usr/bin/env python3
"""
Test script for PrivacyReviewerAgent Chain of Thought generation
"""

from brex_audit.privacy_reviewer_agent import PrivacyReviewerAgent, Severity

def test_pii_in_logs():
    """Test PII exposure in logs with CoT generation."""
    agent = PrivacyReviewerAgent()

    code = '''
import logging
logger.info(f"User email: {user.email}")
logger.debug(f"SSN: {user.ssn}")
'''

    findings = agent.review_file('test.py', code)

    print("=" * 80)
    print("TEST: PII Exposure in Logs")
    print("=" * 80)
    print(f"\nFound {len(findings)} findings\n")

    for f in findings:
        print(f"[{f.severity.value}] {f.category.value} at line {f.line_number}")
        print(f"  Evidence: {f.evidence}")

        if f.chain_of_thought:
            print(f"  ✓ CoT generated")
            print(f"    Detection: {f.chain_of_thought.detection.pattern_matched}")
            print(f"    Risk: {f.chain_of_thought.risk.severity_reasoning[:100]}...")
            print(f"    Compliance: {', '.join(f.chain_of_thought.risk.compliance_impact)}")
            print(f"    Fix: {f.chain_of_thought.remediation.recommended_fix}")
        else:
            print(f"  ✗ No CoT (expected for MEDIUM/LOW findings)")
        print()


def test_missing_encryption():
    """Test missing encryption with CoT generation."""
    agent = PrivacyReviewerAgent()

    code = '''
class User(models.Model):
    ssn = models.CharField(max_length=11)
    credit_card = models.CharField(max_length=16)
    cvv = models.CharField(max_length=3)
'''

    findings = agent.review_file('models.py', code)

    print("=" * 80)
    print("TEST: Missing Encryption")
    print("=" * 80)
    print(f"\nFound {len(findings)} findings\n")

    for f in findings:
        print(f"[{f.severity.value}] {f.category.value} at line {f.line_number}")
        print(f"  Evidence: {f.evidence}")

        if f.chain_of_thought:
            print(f"  ✓ CoT generated")
            print(f"    Detection: {f.chain_of_thought.detection.pattern_matched}")
            print(f"    Compliance: {', '.join(f.chain_of_thought.risk.compliance_impact)}")
            print(f"    Attack: {f.chain_of_thought.attack.attack_vector}")
            print(f"    Exploitability: {f.chain_of_thought.attack.exploitability_rating}")
        else:
            print(f"  ✗ No CoT")
        print()


def test_hipaa_violation():
    """Test HIPAA violation with CoT generation."""
    agent = PrivacyReviewerAgent()

    code = '''
import logging
logger.info(f"Patient {patient_name} diagnosed with {diagnosis}")
'''

    findings = agent.review_file('healthcare.py', code)

    print("=" * 80)
    print("TEST: HIPAA Violation (PHI in Logs)")
    print("=" * 80)
    print(f"\nFound {len(findings)} findings\n")

    for f in findings:
        print(f"[{f.severity.value}] {f.category.value} at line {f.line_number}")
        print(f"  Regulation: {f.regulation_reference}")

        if f.chain_of_thought:
            print(f"  ✓ CoT generated")
            print(f"    Severity: {f.chain_of_thought.risk.severity_reasoning[:120]}...")
            print(f"    Impact: {f.chain_of_thought.risk.impact_description[:120]}...")
            print(f"    Data Sensitivity: {f.chain_of_thought.risk.data_sensitivity}")
        print()


def test_cot_serialization():
    """Test CoT serialization to dict."""
    agent = PrivacyReviewerAgent()

    code = 'logger.info(f"Card: {card_number}")'
    findings = agent.review_file('test.py', code)

    print("=" * 80)
    print("TEST: CoT Serialization")
    print("=" * 80)

    if findings and findings[0].chain_of_thought:
        cot_dict = findings[0].to_dict()

        print("\n✓ Finding serializes to dict successfully")
        print(f"  Keys: {list(cot_dict.keys())}")
        print(f"  CoT Keys: {list(cot_dict['chain_of_thought'].keys())}")
        print(f"  Detection method: {cot_dict['chain_of_thought']['detection']['detection_method']}")
        print(f"  Confidence level: {cot_dict['chain_of_thought']['confidence']['confidence_level']}")
    else:
        print("\n✗ No CoT generated")


def test_severity_filtering():
    """Test that CoT is only generated for HIGH and CRITICAL findings."""
    agent = PrivacyReviewerAgent()

    # This should trigger a MEDIUM or LOW finding without CoT
    code = '''
def collect_user_data():
    # Data collection without visible consent
    user_data = request.form.get('email')
'''

    findings = agent.review_file('data_collection.py', code)

    print("=" * 80)
    print("TEST: CoT Generation Only for HIGH/CRITICAL")
    print("=" * 80)
    print(f"\nFound {len(findings)} findings\n")

    high_critical_count = 0
    medium_low_count = 0

    for f in findings:
        if f.severity in [Severity.HIGH, Severity.CRITICAL]:
            high_critical_count += 1
            has_cot = f.chain_of_thought is not None
            print(f"[{f.severity.value}] {f.category.value}: CoT = {has_cot}")
            if not has_cot:
                print("  ⚠ WARNING: HIGH/CRITICAL finding without CoT!")
        else:
            medium_low_count += 1
            has_cot = f.chain_of_thought is not None
            print(f"[{f.severity.value}] {f.category.value}: CoT = {has_cot}")
            if has_cot:
                print("  ⚠ WARNING: MEDIUM/LOW finding with CoT (unexpected but OK)")


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("PRIVACY REVIEWER AGENT - CHAIN OF THOUGHT TESTS")
    print("=" * 80 + "\n")

    test_pii_in_logs()
    test_missing_encryption()
    test_hipaa_violation()
    test_cot_serialization()
    test_severity_filtering()

    print("\n" + "=" * 80)
    print("ALL TESTS COMPLETED")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test script for PermissionReviewerAgent with Chain of Thought generation.

Tests various permission vulnerability scenarios to ensure CoT is generated
for HIGH and CRITICAL findings.
"""

import sys
from brex_audit.permission_reviewer_agent import PermissionReviewerAgent, Severity

def test_missing_rls():
    """Test missing RLS detection with CoT."""
    print("=" * 80)
    print("TEST 1: Missing Row-Level Security (CRITICAL)")
    print("=" * 80)

    agent = PermissionReviewerAgent()

    code = '''
CREATE TABLE customers (
    id INT,
    tenant_id INT,
    name VARCHAR(100),
    email VARCHAR(100)
);
'''

    findings = agent.review_file("schema.sql", code)

    assert len(findings) > 0, "Should detect missing RLS"

    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0, "Should have CRITICAL findings"

    for f in critical_findings:
        print(f"\n[{f.severity.value}] {f.category.value}")
        print(f"Line {f.line_number}: {f.evidence[:80]}")
        print(f"Recommendation: {f.recommendation[:100]}...")

        # Verify CoT is present
        assert f.chain_of_thought is not None, "CRITICAL finding should have CoT"

        # Verify CoT components
        cot = f.chain_of_thought
        assert "OWASP" in str(cot.risk.compliance_impact), "Should reference OWASP"
        assert "tenant" in cot.risk.severity_reasoning.lower(), "Should mention tenant isolation"
        assert len(cot.attack.attack_steps) > 0, "Should have attack steps"

        print("\n" + "─" * 80)
        print("Chain of Thought Summary:")
        print("─" * 80)
        print(cot.get_summary())

    print("\n✅ TEST 1 PASSED\n")


def test_grant_all_public():
    """Test GRANT ALL to PUBLIC with CoT."""
    print("=" * 80)
    print("TEST 2: GRANT ALL to PUBLIC (HIGH)")
    print("=" * 80)

    agent = PermissionReviewerAgent()

    code = '''
CREATE TABLE sensitive_data (
    id INT,
    secret VARCHAR(100)
);

GRANT ALL PRIVILEGES ON TABLE sensitive_data TO ROLE PUBLIC;
'''

    findings = agent.review_file("grants.sql", code)

    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) > 0, "Should detect HIGH severity findings"

    for f in high_findings:
        print(f"\n[{f.severity.value}] {f.category.value}")
        print(f"Line {f.line_number}: {f.evidence[:80]}")

        # Verify CoT is present for HIGH findings
        assert f.chain_of_thought is not None, "HIGH finding should have CoT"

        cot = f.chain_of_thought
        assert "CIS" in str(cot.risk.compliance_impact), "Should reference CIS"
        assert "least privilege" in cot.risk.severity_reasoning.lower(), "Should mention least privilege"

        print("\n" + "─" * 80)
        print("Chain of Thought Summary:")
        print("─" * 80)
        print(cot.get_summary())

    print("\n✅ TEST 2 PASSED\n")


def test_accountadmin_misuse():
    """Test ACCOUNTADMIN misuse with CoT."""
    print("=" * 80)
    print("TEST 3: ACCOUNTADMIN Misuse (CRITICAL)")
    print("=" * 80)

    agent = PermissionReviewerAgent()

    code = '''
import snowflake.connector

conn = snowflake.connector.connect(
    user='app_user',
    password='secret',
    account='myaccount',
    role='ACCOUNTADMIN'
)
'''

    findings = agent.review_file("app.py", code)

    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0, "Should detect ACCOUNTADMIN misuse"

    for f in critical_findings:
        print(f"\n[{f.severity.value}] {f.category.value}")
        print(f"Line {f.line_number}: {f.evidence[:80]}")

        assert f.chain_of_thought is not None, "CRITICAL finding should have CoT"

        cot = f.chain_of_thought
        assert "account" in cot.risk.impact_description.lower(), "Should mention account impact"
        assert len(cot.remediation.alternative_fixes) > 0, "Should provide alternatives"

        print("\n" + "─" * 80)
        print("Chain of Thought Summary:")
        print("─" * 80)
        print(cot.get_summary())

    print("\n✅ TEST 3 PASSED\n")


def test_missing_ownership_check():
    """Test missing ownership check (BOLA) with CoT."""
    print("=" * 80)
    print("TEST 4: Missing Ownership Check - BOLA/IDOR (HIGH)")
    print("=" * 80)

    agent = PermissionReviewerAgent()

    code = '''
UPDATE orders
SET status = 'cancelled',
    updated_at = NOW()
WHERE order_id = 123;
'''

    findings = agent.review_file("queries.sql", code)

    # Should detect HIGH or CRITICAL finding for UPDATE without ownership check
    high_or_critical = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
    assert len(high_or_critical) > 0, "Should detect missing ownership check"

    for f in high_or_critical:
        print(f"\n[{f.severity.value}] {f.category.value}")
        print(f"Line {f.line_number}: {f.evidence[:80]}")

        assert f.chain_of_thought is not None, f"{f.severity} finding should have CoT"

        cot = f.chain_of_thought
        assert "BOLA" in str(cot.risk.compliance_impact) or "ownership" in cot.risk.severity_reasoning.lower(), \
            "Should reference BOLA or ownership"

        print("\n" + "─" * 80)
        print("Chain of Thought Summary:")
        print("─" * 80)
        print(cot.get_summary())

    print("\n✅ TEST 4 PASSED\n")


def test_multiple_findings():
    """Test file with multiple permission issues."""
    print("=" * 80)
    print("TEST 5: Multiple Permission Issues")
    print("=" * 80)

    agent = PermissionReviewerAgent()

    code = '''
-- Missing RLS
CREATE TABLE orders (
    id INT,
    tenant_id INT,
    amount DECIMAL(10,2)
);

-- Over-broad grant
GRANT ALL ON DATABASE sales TO ROLE PUBLIC;

-- ACCOUNTADMIN misuse
USE ROLE ACCOUNTADMIN;

-- Insecure view
CREATE VIEW order_summary AS
SELECT * FROM orders;
'''

    findings = agent.review_file("multi_issues.sql", code)

    print(f"\nFound {len(findings)} findings")

    # Count findings with CoT
    findings_with_cot = [f for f in findings if f.chain_of_thought is not None]
    high_critical = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]

    print(f"HIGH/CRITICAL findings: {len(high_critical)}")
    print(f"Findings with CoT: {len(findings_with_cot)}")

    # All HIGH/CRITICAL should have CoT
    assert len(findings_with_cot) == len(high_critical), \
        "All HIGH/CRITICAL findings should have CoT"

    for f in findings:
        print(f"\n[{f.severity.value}] {f.category.value} - Line {f.line_number}")
        if f.chain_of_thought:
            print("  ✓ Has Chain of Thought")
            print(f"  Risk: {f.chain_of_thought.risk.severity_reasoning[:80]}...")
            print(f"  Exploitability: {f.chain_of_thought.attack.exploitability_rating}")

    print("\n✅ TEST 5 PASSED\n")


def test_cot_serialization():
    """Test CoT serialization to dict."""
    print("=" * 80)
    print("TEST 6: CoT Serialization")
    print("=" * 80)

    agent = PermissionReviewerAgent()

    code = '''
CREATE TABLE users (id INT, tenant_id INT, name VARCHAR);
'''

    findings = agent.review_file("test.sql", code)

    for f in findings:
        if f.chain_of_thought:
            # Test to_dict serialization
            finding_dict = f.to_dict()

            assert "chain_of_thought" in finding_dict, "Should have CoT in dict"
            assert "detection" in finding_dict["chain_of_thought"], "Should have detection"
            assert "risk" in finding_dict["chain_of_thought"], "Should have risk"
            assert "attack" in finding_dict["chain_of_thought"], "Should have attack"
            assert "confidence" in finding_dict["chain_of_thought"], "Should have confidence"
            assert "remediation" in finding_dict["chain_of_thought"], "Should have remediation"

            print("✓ Finding serializes to dict correctly")
            print(f"✓ CoT keys: {list(finding_dict['chain_of_thought'].keys())}")

            # Test JSON serialization
            import json
            json_str = json.dumps(finding_dict, indent=2)
            print(f"✓ Serializes to JSON ({len(json_str)} bytes)")

            break

    print("\n✅ TEST 6 PASSED\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("PERMISSION REVIEWER AGENT - CHAIN OF THOUGHT TESTS")
    print("=" * 80 + "\n")

    try:
        test_missing_rls()
        test_grant_all_public()
        test_accountadmin_misuse()
        test_missing_ownership_check()
        test_multiple_findings()
        test_cot_serialization()

        print("=" * 80)
        print("✅ ALL TESTS PASSED")
        print("=" * 80)
        return 0

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

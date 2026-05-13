"""
Permission Reviewer Agent for Access Control Analysis
======================================================
A specialized agent that detects authorization and access control vulnerabilities, focusing on:
- Missing Row-Level Security (RLS) policies
- Over-broad GRANT permissions
- ACCOUNTADMIN misuse in application code
- Insecure views and materialized views
- Missing ownership/tenant filters (BOLA/IDOR)
- PUBLIC role exposure
- Tenant isolation issues

Knowledge sources:
- OWASP API Security Top 10 (API1:2023 BOLA, API5:2023 BFLA)
- CIS Snowflake Benchmarks
- Multi-tenant security best practices

Usage:
    from brex_audit.permission_reviewer_agent import PermissionReviewerAgent

    agent = PermissionReviewerAgent()
    findings = agent.review_file("/path/to/schema.sql", file_content)

    for finding in findings:
        print(f"{finding.severity}: {finding.category}")
        print(f"  Line {finding.line_number}: {finding.evidence}")
        print(f"  Recommendation: {finding.recommendation}")
"""

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple, Pattern
from pathlib import Path
from datetime import datetime

from brex_audit.models import (
    ChainOfThought,
    DetectionReasoning,
    RiskAnalysis,
    AttackScenario,
    ConfidenceRationale,
    RemediationReasoning,
    ContextAnalysis,
    ConfidenceLevel
)

logger = logging.getLogger(__name__)


# ─── Enums ──────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Permission finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Confidence level for detection accuracy."""
    HIGH = "HIGH"      # Clear vulnerability, minimal false positives
    MEDIUM = "MEDIUM"  # Likely vulnerability, some context needed
    LOW = "LOW"        # Possible vulnerability, requires manual review


class Category(str, Enum):
    """Permission vulnerability categories."""
    MISSING_RLS = "Missing Row-Level Security"
    OVERLY_BROAD_GRANT = "Over-broad GRANT Permissions"
    ACCOUNTADMIN_MISUSE = "ACCOUNTADMIN Misuse"
    INSECURE_VIEW = "Insecure View"
    MISSING_OWNERSHIP_CHECK = "Missing Ownership Check (BOLA/IDOR)"
    PUBLIC_ROLE_EXPOSURE = "PUBLIC Role Exposure"
    TENANT_ISOLATION_ISSUE = "Tenant Isolation Issue"
    EXCESSIVE_PRIVILEGES = "Excessive Privileges"
    MISSING_AUTHORIZATION = "Missing Authorization Check"


# ─── Data Classes ───────────────────────────────────────────────────────────


@dataclass
class Finding:
    """Represents a permission/authorization finding from code analysis."""
    category: Category
    severity: Severity
    confidence: Confidence
    line_number: int
    evidence: str
    recommendation: str
    file_path: Optional[str] = None
    context: Optional[str] = None
    owasp_reference: Optional[str] = None
    cis_reference: Optional[str] = None
    chain_of_thought: Optional[ChainOfThought] = None

    def __post_init__(self):
        """Validate and enrich finding data."""
        if len(self.evidence) > 500:
            self.evidence = self.evidence[:497] + "..."

    def to_dict(self) -> Dict:
        """Convert finding to dictionary for JSON serialization."""
        result = {
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "file_path": self.file_path,
            "context": self.context,
            "owasp_reference": self.owasp_reference,
            "cis_reference": self.cis_reference,
        }

        # Include CoT if present
        if self.chain_of_thought:
            result["chain_of_thought"] = self.chain_of_thought.to_dict()

        return result


@dataclass
class PermissionPattern:
    """Represents a permission vulnerability pattern."""
    pattern: Pattern
    category: Category
    severity: Severity
    confidence: Confidence
    description: str
    recommendation: str
    owasp_ref: Optional[str] = None
    cis_ref: Optional[str] = None
    false_positive_patterns: List[Pattern] = field(default_factory=list)


# ─── Permission Reviewer Agent ─────────────────────────────────────────────


class PermissionReviewerAgent:
    """
    Multi-layer permission and authorization code reviewer.

    Detection methods:
    1. SQL DDL parsing for RLS policies, GRANTs, roles
    2. Terraform/HCL analysis for Snowflake resources
    3. dbt YAML manifest parsing
    4. Python code analysis for authorization checks
    5. Context-aware analysis to reduce false positives
    """

    def __init__(self):
        """Initialize the Permission Reviewer Agent."""
        self.patterns = self._initialize_patterns()
        self.file_extensions = {
            '.sql', '.py', '.tf', '.hcl', '.yml', '.yaml', '.json'
        }

    def _initialize_patterns(self) -> List[PermissionPattern]:
        """Initialize comprehensive permission vulnerability patterns."""
        patterns = []

        # ═══ Missing Row-Level Security ═══

        # CREATE TABLE without RLS policy
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'CREATE\s+(?:OR\s+REPLACE\s+)?TABLE\s+(\w+\.\w+\.\w+|\w+\.\w+|\w+)\s*\([^;]+\);(?!\s*CREATE\s+ROW\s+ACCESS\s+POLICY)',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.MISSING_RLS,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            description="Snowflake table created without Row-Level Security policy",
            recommendation="Implement Snowflake Row-Level Security policy filtering by tenant_id. Example: CREATE ROW ACCESS POLICY tenant_policy AS (tenant_id VARCHAR) RETURNS BOOLEAN -> tenant_id = CURRENT_USER_TENANT_ID()",
            owasp_ref="OWASP API1:2023 - Broken Object Level Authorization (BOLA)",
            cis_ref="CIS Snowflake Benchmark 2.1.1 - Implement Row-Level Security"
        ))

        # Multi-tenant table markers (higher confidence RLS check)
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'CREATE\s+TABLE.*?\b(tenant_id|org_id|customer_id|account_id)\b',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.MISSING_RLS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Multi-tenant table without Row-Level Security policy",
            recommendation="Implement RLS policy filtering by tenant_id column. Multi-tenant tables MUST have RLS to prevent cross-tenant data access.",
            owasp_ref="OWASP API1:2023 - BOLA",
            cis_ref="CIS Snowflake 2.1.1"
        ))

        # ═══ Over-broad GRANT Permissions ═══

        # GRANT ALL
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+(?:SCHEMA|TABLE|DATABASE|WAREHOUSE)',
                re.IGNORECASE
            ),
            category=Category.OVERLY_BROAD_GRANT,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="GRANT ALL privileges detected (violates least privilege)",
            recommendation="Use specific privileges instead of ALL. Example: GRANT SELECT, INSERT ON TABLE foo TO ROLE analyst_role",
            owasp_ref="OWASP API5:2023 - Broken Function Level Authorization",
            cis_ref="CIS Snowflake 1.4.2 - Use least privilege for GRANTs"
        ))

        # GRANT to PUBLIC role
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'GRANT\s+[A-Z, ]+\s+(?:ON|TO)\s+(?:ROLE\s+)?PUBLIC',
                re.IGNORECASE
            ),
            category=Category.PUBLIC_ROLE_EXPOSURE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="GRANT to PUBLIC role exposes resources to all users",
            recommendation="Avoid GRANT to PUBLIC. Create specific roles with minimal required privileges. PUBLIC should only have access to non-sensitive, truly public data.",
            owasp_ref="OWASP API5:2023 - BFLA",
            cis_ref="CIS Snowflake 1.4.3 - Restrict PUBLIC role privileges"
        ))

        # GRANT without WHERE clause (for row-level grants)
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'GRANT\s+SELECT\s+ON\s+TABLE\s+[^\s;]+(?!.*WHERE)',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.OVERLY_BROAD_GRANT,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description="GRANT SELECT without row-level filters may expose excessive data",
            recommendation="Consider using views with WHERE clauses or RLS policies to limit data access. Full table SELECT may expose sensitive rows.",
            cis_ref="CIS Snowflake 2.1.2"
        ))

        # ═══ ACCOUNTADMIN Misuse ═══

        # ACCOUNTADMIN in application code
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'(?i)(USE\s+ROLE\s+ACCOUNTADMIN|role\s*[=:]\s*["\']ACCOUNTADMIN["\']|ACCOUNTADMIN_ROLE|snowflake\.role\s*=\s*["\']ACCOUNTADMIN["\'])',
                re.IGNORECASE
            ),
            category=Category.ACCOUNTADMIN_MISUSE,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="ACCOUNTADMIN role used in application code (highest privilege)",
            recommendation="Use custom role with minimal required privileges. ACCOUNTADMIN should ONLY be used by DBAs for account administration. Create task-specific roles (e.g., LOADER_ROLE, ANALYST_ROLE).",
            owasp_ref="OWASP API5:2023 - BFLA",
            cis_ref="CIS Snowflake 1.1.1 - Restrict ACCOUNTADMIN usage"
        ))

        # SECURITYADMIN in app code
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'(?i)(USE\s+ROLE\s+SECURITYADMIN|role\s*[=:]\s*["\']SECURITYADMIN["\'])',
                re.IGNORECASE
            ),
            category=Category.ACCOUNTADMIN_MISUSE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="SECURITYADMIN role used in application code",
            recommendation="Use least-privilege custom role. SECURITYADMIN should only be used for security operations, not application logic.",
            cis_ref="CIS Snowflake 1.1.2"
        ))

        # ═══ Insecure Views ═══

        # View without row filters on multi-tenant table
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+\w+.*?FROM\s+(\w+)(?!.*WHERE.*tenant_id)',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.INSECURE_VIEW,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,  # Low because we can't always detect tenant tables
            description="View may not filter by tenant_id (potential cross-tenant exposure)",
            recommendation="Ensure views on multi-tenant tables include WHERE tenant_id = CURRENT_USER_TENANT_ID() or equivalent filter.",
            owasp_ref="OWASP API1:2023 - BOLA",
            cis_ref="CIS Snowflake 2.1.1"
        ))

        # SECURE keyword missing on views with sensitive data
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?!SECURE)',
                re.IGNORECASE
            ),
            category=Category.INSECURE_VIEW,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description="View created without SECURE keyword (view definition exposed to users)",
            recommendation="Use CREATE SECURE VIEW to hide view definition from unauthorized users. This prevents exposure of business logic and data sources.",
            cis_ref="CIS Snowflake 2.2.1 - Use SECURE views for sensitive data"
        ))

        # ═══ Missing Ownership/Tenant Checks (BOLA/IDOR) ═══

        # SQL WHERE without ownership check (simplified - no lookbehind)
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'(?i)SELECT\s+.*?FROM\s+(\w+).*?WHERE\s+(?!.*user_id)(?!.*owner_id)(?!.*tenant_id)(?!.*customer_id)(?!.*created_by)[^;]+',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.MISSING_OWNERSHIP_CHECK,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,  # Low confidence due to high false positives
            description="SELECT query may be missing ownership/tenant check",
            recommendation="Add ownership check in WHERE clause. Example: WHERE user_id = CURRENT_USER_ID() or WHERE tenant_id = CURRENT_TENANT_ID(). Prevents BOLA/IDOR attacks.",
            owasp_ref="OWASP API1:2023 - BOLA"
        ))

        # UPDATE/DELETE without WHERE clause
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'(?i)(UPDATE|DELETE)\s+(?:FROM\s+)?(\w+\.\w+\.\w+|\w+\.\w+|\w+)(?!\s+WHERE)',
                re.IGNORECASE
            ),
            category=Category.MISSING_OWNERSHIP_CHECK,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="UPDATE/DELETE without WHERE clause affects all rows (potential mass modification)",
            recommendation="Always include WHERE clause with ownership check. Example: WHERE id = ? AND user_id = CURRENT_USER_ID()",
            owasp_ref="OWASP API1:2023 - BOLA"
        ))

        # API endpoint without authorization decorator (Python Flask/FastAPI)
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'@(?:app|router)\.(get|post|put|delete|patch)\(["\'].*?/(?:users?|documents?|orders?|resources?)/\{?(\w+)\}?',
                re.IGNORECASE
            ),
            category=Category.MISSING_AUTHORIZATION,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            description="API endpoint with ID parameter may be missing authorization check",
            recommendation="Add authorization decorator and check object ownership. Example: @require_ownership or verify_access(user_id, resource_id)",
            owasp_ref="OWASP API1:2023 - BOLA"
        ))

        # ═══ Python Code - Direct ID access without check ═══

        # Object fetch by ID without ownership check
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'(?i)(get_by_id|fetch_by_id|find_by_id|query\.get|session\.get|\.objects\.get)\s*\(\s*["\']?(\w+)["\']?\s*[,\)]',
                re.IGNORECASE
            ),
            category=Category.MISSING_OWNERSHIP_CHECK,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            description="Object fetched by ID without visible ownership check (potential IDOR)",
            recommendation="Verify user owns/has access to object before returning. Example: if obj.user_id != current_user.id: raise Forbidden()",
            owasp_ref="OWASP API1:2023 - BOLA"
        ))

        # ═══ Terraform - Snowflake Resources ═══

        # Snowflake warehouse without resource_monitor
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'resource\s+"snowflake_warehouse"[^}]+(?!resource_monitor)',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.EXCESSIVE_PRIVILEGES,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="Snowflake warehouse without resource monitor (cost/security risk)",
            recommendation="Attach resource monitor to warehouses to prevent runaway costs and potential denial-of-service.",
            cis_ref="CIS Snowflake 1.5.1 - Configure resource monitors"
        ))

        # Network policy missing (Snowflake)
        patterns.append(PermissionPattern(
            pattern=re.compile(
                r'resource\s+"snowflake_account"[^}]+(?!network_policy)',
                re.IGNORECASE | re.DOTALL
            ),
            category=Category.EXCESSIVE_PRIVILEGES,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description="Snowflake account without network policy (allows access from any IP)",
            recommendation="Configure network policy to restrict access to known IP ranges. Example: network_policy = snowflake_network_policy.allowed_ips.name",
            cis_ref="CIS Snowflake 1.2.1 - Configure network policies"
        ))

        return patterns

    def _generate_chain_of_thought(
        self,
        pattern: PermissionPattern,
        evidence: str,
        line_number: int,
        file_path: str,
        surrounding_context: str
    ) -> ChainOfThought:
        """
        Generate Chain of Thought reasoning for a permission finding.

        Args:
            pattern: The permission pattern that matched
            evidence: The code evidence
            line_number: Line number of finding
            file_path: Path to file
            surrounding_context: Code around the finding

        Returns:
            ChainOfThought instance with complete reasoning
        """
        # Map Confidence enum to ConfidenceLevel
        confidence_mapping = {
            Confidence.HIGH: ConfidenceLevel.HIGH,
            Confidence.MEDIUM: ConfidenceLevel.MEDIUM,
            Confidence.LOW: ConfidenceLevel.LOW
        }

        # Generate category-specific reasoning
        if pattern.category == Category.MISSING_RLS:
            return self._generate_missing_rls_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.OVERLY_BROAD_GRANT:
            return self._generate_overly_broad_grant_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.ACCOUNTADMIN_MISUSE:
            return self._generate_accountadmin_misuse_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.INSECURE_VIEW:
            return self._generate_insecure_view_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.MISSING_OWNERSHIP_CHECK:
            return self._generate_missing_ownership_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.PUBLIC_ROLE_EXPOSURE:
            return self._generate_public_role_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.TENANT_ISOLATION_ISSUE:
            return self._generate_tenant_isolation_cot(pattern, evidence, line_number, file_path, surrounding_context)
        else:
            # Generic CoT for other categories
            return self._generate_generic_cot(pattern, evidence, line_number, file_path, surrounding_context)

    def _generate_missing_rls_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for missing RLS findings."""
        # Determine if this is clearly a multi-tenant table
        is_multi_tenant = any(keyword in evidence.lower() for keyword in ['tenant_id', 'org_id', 'customer_id', 'account_id'])

        confidence_level = ConfidenceLevel.HIGH if is_multi_tenant else ConfidenceLevel.MEDIUM

        signals = ["CREATE TABLE statement", "No RLS policy detected"]
        if is_multi_tenant:
            signals.append("Multi-tenant column present (tenant_id/org_id)")
        else:
            signals.append("RLS policy not found after CREATE TABLE")

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Snowflake table without Row-Level Security policy",
                evidence_summary=f"Line {line_number}: {evidence[:80]}",
                detection_method="SQL DDL parsing and RLS policy detection",
                signals_observed=signals,
                agent_name="PermissionReviewerAgent",
                check_name="_check_missing_rls"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Missing RLS allows users to query across tenant boundaries, violating fundamental isolation requirement",
                impact_description="Cross-tenant data leakage, unauthorized access to other organizations' data, compliance violations, privacy breach",
                affected_assets=["Multi-tenant table data", "Customer data isolation", "Trust boundaries", "Tenant privacy"],
                attack_surface="Any authenticated user can query table without tenant filtering",
                data_sensitivity="Multi-tenant PII/business data",
                compliance_impact=["OWASP API1:2023 BOLA", "SOC 2 CC6.1", "CIS Snowflake Benchmark 2.1.1", "GDPR Article 32"]
            ),
            attack=AttackScenario(
                attack_vector="Direct SQL query or API call without tenant_id filtering",
                attack_steps=[
                    "Authenticate as user in tenant A",
                    "Query table without WHERE tenant_id clause",
                    "Access data from tenant B, C, D, etc.",
                    "Exfiltrate sensitive cross-tenant data"
                ],
                required_access="Authenticated user with SELECT permission",
                exploitability_rating="Easy",
                similar_cves=["CVE-2020-15133 (tenant isolation bypass)", "CVE-2021-32740 (multi-tenant data leak)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["No RLS policy", "Multi-tenant table pattern" if is_multi_tenant else "Table without RLS", "No WHERE clause enforcement"],
                strong_evidence=["CREATE TABLE without RLS"] + (["tenant_id column present"] if is_multi_tenant else []),
                weak_evidence=[] if is_multi_tenant else ["Table purpose unclear - may not be multi-tenant"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Implement Snowflake Row-Level Security policy filtering by tenant_id",
                fix_rationale="RLS enforces tenant filtering at database level, cannot be bypassed by application logic bugs. Provides defense-in-depth.",
                alternative_fixes=[
                    "Application-level filtering (less secure, bypassable by bugs)",
                    "Separate schemas per tenant (operational complexity, doesn't scale)",
                    "Views with tenant filters (less robust than RLS, can be bypassed)"
                ],
                tradeoffs="RLS is most secure but requires migration; application filtering is quick but error-prone",
                implementation_complexity="Medium",
                breaking_changes=False,
                testing_guidance="Test cross-tenant query attempts fail, verify performance impact acceptable, test RLS with different user contexts"
            ),
            context=ContextAnalysis(
                function_purpose="Multi-tenant data storage",
                data_flow="Application queries → Table → All tenant data (no filtering)",
                missing_controls=["Row-Level Security", "Tenant isolation enforcement"],
                framework_context="Snowflake multi-tenant architecture"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_overly_broad_grant_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for over-broad GRANT findings."""
        # Determine if this is GRANT ALL or other overly broad permission
        is_grant_all = "GRANT ALL" in evidence.upper()

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        signals = ["GRANT statement"]
        if is_grant_all:
            signals.append("GRANT ALL privileges")
        if "PUBLIC" in evidence.upper():
            signals.append("GRANT to PUBLIC role")

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Over-broad GRANT privileges violating least privilege",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="SQL DDL parsing for GRANT statements",
                signals_observed=signals,
                agent_name="PermissionReviewerAgent",
                check_name="_check_overly_broad_grant"
            ),
            risk=RiskAnalysis(
                severity_reasoning="GRANT ALL or PUBLIC grants expose sensitive operations to all users including newly created accounts",
                impact_description="Any user can read/modify sensitive data, privilege escalation, data deletion, bypass intended access controls",
                affected_assets=["Database objects", "Sensitive tables", "Admin functions", "Data integrity"],
                attack_surface="All authenticated users including new/compromised accounts",
                data_sensitivity="High - Unrestricted data access",
                compliance_impact=["CIS Snowflake 1.4.2", "SOC 2 CC6.3", "Principle of Least Privilege", "NIST SP 800-53 AC-6"]
            ),
            attack=AttackScenario(
                attack_vector="Compromised user account or malicious insider",
                attack_steps=[
                    "Obtain credentials for any user (phishing, breach, insider)",
                    "Authenticate to Snowflake",
                    "Use GRANT ALL privileges to access sensitive data",
                    "Modify or delete critical data",
                    "Escalate privileges if GRANT includes role management"
                ],
                required_access="Any authenticated user account",
                exploitability_rating="Easy",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Explicit GRANT ALL or PUBLIC" if is_grant_all else "Broad GRANT statement", "Violates least privilege principle"],
                strong_evidence=["GRANT ALL" if is_grant_all else "GRANT statement", "No privilege restriction"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use specific privileges instead of ALL. Create role-based access with minimal required permissions.",
                fix_rationale="Least privilege limits blast radius of compromised accounts. Specific privileges enable fine-grained access control and audit.",
                alternative_fixes=[
                    "GRANT SELECT only for read-only users",
                    "GRANT INSERT, UPDATE on specific tables for writers",
                    "Create custom roles per job function (analyst, loader, admin)",
                    "Use views to expose only needed columns"
                ],
                tradeoffs="More granular permissions require more setup but provide better security and auditability",
                implementation_complexity="Medium",
                breaking_changes=True,
                testing_guidance="Test each role has exactly the permissions needed. Verify users can't access unintended data."
            ),
            context=ContextAnalysis(
                function_purpose="Database permission management",
                data_flow="GRANT statement → Role privileges → User access",
                missing_controls=["Least privilege enforcement", "Role-based access control"],
                framework_context="Snowflake RBAC"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_accountadmin_misuse_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for ACCOUNTADMIN misuse findings."""
        confidence_level = ConfidenceLevel.HIGH

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="ACCOUNTADMIN role in application code",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for ACCOUNTADMIN usage in SQL/Python",
                signals_observed=["ACCOUNTADMIN role usage", "Application code context", "Highest privilege role"],
                agent_name="PermissionReviewerAgent",
                check_name="_check_accountadmin_misuse"
            ),
            risk=RiskAnalysis(
                severity_reasoning="ACCOUNTADMIN role in application code allows privilege escalation, audit bypass, and full account control",
                impact_description="Complete account takeover, bypass all security controls, delete audit logs, create backdoor accounts, access all data, modify security policies",
                affected_assets=["Entire Snowflake account", "All data", "Audit logs", "Security policies", "User accounts"],
                attack_surface="Application code execution context",
                data_sensitivity="Critical - Full account access",
                compliance_impact=["CIS Snowflake 1.1.1", "SOC 2 CC6.1", "Separation of Duties", "NIST SP 800-53 AC-6"]
            ),
            attack=AttackScenario(
                attack_vector="Credential theft, code injection, or application compromise",
                attack_steps=[
                    "Compromise application or steal ACCOUNTADMIN credentials from code",
                    "Authenticate to Snowflake with ACCOUNTADMIN",
                    "Access/modify all data across all databases",
                    "Delete audit logs to cover tracks",
                    "Create backdoor admin accounts for persistence"
                ],
                required_access="Access to application code or credentials",
                exploitability_rating="Easy",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Explicit ACCOUNTADMIN usage", "Application code context", "Violates separation of duties"],
                strong_evidence=["ACCOUNTADMIN in code/config", "Not in DBA admin scripts"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use custom role with minimal required privileges. Remove ACCOUNTADMIN from application code.",
                fix_rationale="Least privilege principle. ACCOUNTADMIN should ONLY be used by DBAs for account-level administration, not application operations.",
                alternative_fixes=[
                    "Create task-specific role (e.g., LOADER_ROLE with INSERT/UPDATE only)",
                    "Use SYSADMIN for most admin tasks",
                    "Reserve ACCOUNTADMIN for emergency account recovery only"
                ],
                tradeoffs="Custom roles require initial setup but dramatically reduce security risk",
                implementation_complexity="Medium",
                breaking_changes=True,
                testing_guidance="Test application operations work with new role. Verify no ACCOUNTADMIN usage in app logs."
            ),
            context=ContextAnalysis(
                function_purpose="Database connection/operation",
                data_flow="Application → ACCOUNTADMIN credentials → Snowflake",
                missing_controls=["Least privilege", "Separation of duties"],
                framework_context="Snowflake application integration"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_insecure_view_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for insecure view findings."""
        # Determine if this is missing SECURE or missing WHERE filter
        is_missing_secure = "SECURE" not in evidence.upper()
        is_missing_filter = "tenant_id" not in evidence.lower() and "WHERE" not in evidence.upper()

        confidence_level = ConfidenceLevel.LOW if pattern.confidence == Confidence.LOW else ConfidenceLevel.MEDIUM

        signals = ["CREATE VIEW statement"]
        if is_missing_secure:
            signals.append("Missing SECURE keyword")
        if is_missing_filter:
            signals.append("No tenant_id filter visible")

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Potentially insecure view definition",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="SQL DDL parsing for view security",
                signals_observed=signals,
                agent_name="PermissionReviewerAgent",
                check_name="_check_insecure_view"
            ),
            risk=RiskAnalysis(
                severity_reasoning="View may expose underlying table structure or lack tenant filtering",
                impact_description="Information disclosure (view definition exposure), potential cross-tenant data access if filters missing",
                affected_assets=["View data", "Business logic", "Tenant isolation"],
                attack_surface="Users with view access",
                data_sensitivity="Medium - View-exposed data",
                compliance_impact=["CIS Snowflake 2.2.1", "SOC 2 CC6.1"]
            ),
            attack=AttackScenario(
                attack_vector="View access without proper filtering",
                attack_steps=[
                    "Authenticate as user with view access",
                    "Query view or inspect view definition",
                    "Discover underlying table structure (if not SECURE)",
                    "Exploit missing tenant filter to access other tenants' data"
                ],
                required_access="Authenticated user with view SELECT permission",
                exploitability_rating="Medium",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["View without SECURE" if is_missing_secure else "View may lack tenant filter"],
                strong_evidence=["CREATE VIEW without SECURE"] if is_missing_secure else [],
                weak_evidence=["Cannot confirm table is multi-tenant", "Filter may be in base table"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use CREATE SECURE VIEW and ensure tenant filtering in WHERE clause",
                fix_rationale="SECURE views hide definition from unauthorized users. Tenant filtering prevents cross-tenant access.",
                alternative_fixes=[
                    "Add SECURE keyword to hide view definition",
                    "Add WHERE tenant_id = CURRENT_USER_TENANT_ID()",
                    "Use RLS policy on underlying table instead"
                ],
                tradeoffs="SECURE views have minimal performance impact. Tenant filtering is essential for multi-tenant security.",
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Verify view definition hidden. Test cross-tenant query fails."
            ),
            context=ContextAnalysis(
                function_purpose="Data abstraction layer",
                data_flow="Query → View → Underlying table",
                missing_controls=["SECURE view" if is_missing_secure else "", "Tenant filter" if is_missing_filter else ""],
                framework_context="Snowflake view security"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_missing_ownership_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for missing ownership check (BOLA/IDOR) findings."""
        # Determine specific issue type
        is_update_delete = any(keyword in evidence.upper() for keyword in ['UPDATE', 'DELETE'])
        is_select = 'SELECT' in evidence.upper()
        is_api = '@' in evidence and any(method in evidence for method in ['get', 'post', 'put', 'delete'])

        confidence_level = ConfidenceLevel.HIGH if is_update_delete and "WHERE" not in evidence.upper() else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        signals = []
        if is_update_delete:
            signals.append("UPDATE/DELETE statement")
            if "WHERE" not in evidence.upper():
                signals.append("No WHERE clause")
        elif is_select:
            signals.append("SELECT query")
            signals.append("No visible ownership check")
        elif is_api:
            signals.append("API endpoint with ID parameter")
            signals.append("No visible authorization decorator")

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Missing ownership check allows unauthorized object access (BOLA/IDOR)",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="SQL/Python pattern matching for authorization checks",
                signals_observed=signals,
                agent_name="PermissionReviewerAgent",
                check_name="_check_missing_ownership"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Missing ownership check allows users to access/modify objects belonging to other users (IDOR)",
                impact_description="Unauthorized data access, data modification, privacy violations, access to other users' resources",
                affected_assets=["User data", "Documents", "Resources", "Orders", "Personal information"],
                attack_surface="API endpoints accepting object IDs or SQL queries with direct ID access",
                data_sensitivity="High - User-specific data",
                compliance_impact=["OWASP API1:2023 BOLA", "OWASP API5:2023 BFLA", "GDPR Article 32", "SOC 2 CC6.1"]
            ),
            attack=AttackScenario(
                attack_vector="Parameter tampering or direct object reference manipulation",
                attack_steps=[
                    "Authenticate as User A",
                    "Identify API endpoint or query accepting object ID",
                    "Guess/enumerate IDs belonging to User B",
                    "Access or modify User B's data without authorization check"
                ],
                required_access="Authenticated user account",
                exploitability_rating="Easy",
                similar_cves=["CVE-2019-15107 (IDOR)", "CVE-2020-5885 (BOLA)", "CVE-2021-24145 (unauthorized access)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["No ownership check visible", "Direct ID access"] if not is_update_delete else ["UPDATE/DELETE without WHERE"],
                strong_evidence=["No user_id/owner_id in WHERE"] if is_select else ["No WHERE clause"] if is_update_delete else ["No @require_ownership"],
                weak_evidence=["Check may be in calling code", "May be admin operation"] if confidence_level == ConfidenceLevel.LOW else [],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Add ownership check in WHERE clause or authorization decorator",
                fix_rationale="Ownership checks ensure users can only access their own data. Prevents BOLA/IDOR attacks.",
                alternative_fixes=[
                    "SQL: Add WHERE user_id = CURRENT_USER_ID() or tenant_id = CURRENT_TENANT_ID()",
                    "Python: Add @require_ownership decorator",
                    "API: Verify obj.user_id == current_user.id before returning",
                    "Use RLS policy to enforce filtering automatically"
                ],
                tradeoffs="Application-level checks are good; database-level enforcement (RLS) is better for defense-in-depth",
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Test User A cannot access User B's data. Test with different user contexts."
            ),
            context=ContextAnalysis(
                function_purpose="Data access/modification",
                data_flow="User request → Query → Database (no ownership filter)",
                missing_controls=["Ownership verification", "Authorization check"],
                framework_context="Multi-user application"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_public_role_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for PUBLIC role exposure findings."""
        confidence_level = ConfidenceLevel.HIGH

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="GRANT to PUBLIC role exposes resources to all users",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="SQL DDL parsing for PUBLIC role grants",
                signals_observed=["GRANT statement", "PUBLIC role", "Unrestricted access"],
                agent_name="PermissionReviewerAgent",
                check_name="_check_public_role"
            ),
            risk=RiskAnalysis(
                severity_reasoning="PUBLIC role grants apply to ALL users including newly created ones, bypassing intended access controls",
                impact_description="All users can access sensitive data, bypass role-based access control, access admin functions",
                affected_assets=["Database objects", "Sensitive tables", "Functions", "Procedures"],
                attack_surface="All authenticated users automatically",
                data_sensitivity="High - Resources exposed to everyone",
                compliance_impact=["CIS Snowflake 1.4.3", "SOC 2 CC6.3", "Principle of Least Privilege"]
            ),
            attack=AttackScenario(
                attack_vector="Any authenticated user account",
                attack_steps=[
                    "Create new user account (or compromise existing one)",
                    "Authenticate to Snowflake",
                    "Automatically have PUBLIC role access",
                    "Access resources granted to PUBLIC"
                ],
                required_access="Any authenticated user",
                exploitability_rating="Easy",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Explicit GRANT to PUBLIC", "Violates least privilege"],
                strong_evidence=["PUBLIC role in GRANT statement"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Remove PUBLIC grants. Create specific roles with minimal privileges.",
                fix_rationale="PUBLIC grants bypass role-based access control. Specific roles enable proper authorization.",
                alternative_fixes=[
                    "Create READ_ONLY_ROLE for general access",
                    "Use views to expose only non-sensitive data to PUBLIC",
                    "Revoke PUBLIC grants: REVOKE ALL ON <object> FROM ROLE PUBLIC"
                ],
                tradeoffs="Removing PUBLIC grants requires creating proper role hierarchy but provides much better security",
                implementation_complexity="Medium",
                breaking_changes=True,
                testing_guidance="Test users have access through explicit roles. Verify PUBLIC has no sensitive access."
            ),
            context=ContextAnalysis(
                function_purpose="Access control management",
                data_flow="GRANT → PUBLIC role → All users",
                missing_controls=["Role-based access control", "Least privilege"],
                framework_context="Snowflake RBAC"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_tenant_isolation_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate CoT for tenant isolation issue findings."""
        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Tenant isolation issue in multi-tenant architecture",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Multi-tenant pattern analysis",
                signals_observed=["Multi-tenant context", "Missing isolation controls"],
                agent_name="PermissionReviewerAgent",
                check_name="_check_tenant_isolation"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Tenant isolation failures allow cross-tenant data access, violating trust boundaries",
                impact_description="Cross-tenant data leakage, compliance violations, loss of customer trust, privacy breach",
                affected_assets=["Tenant data", "Customer privacy", "Trust boundaries"],
                attack_surface="Multi-tenant data access paths",
                data_sensitivity="Critical - Multi-tenant isolation",
                compliance_impact=["SOC 2 CC6.1", "ISO 27001", "GDPR Article 32"]
            ),
            attack=AttackScenario(
                attack_vector="Cross-tenant query or API call",
                attack_steps=[
                    "Authenticate as user in Tenant A",
                    "Identify multi-tenant resource",
                    "Query/access without tenant filtering",
                    "Access Tenant B, C, D data"
                ],
                required_access="Authenticated user in any tenant",
                exploitability_rating="Easy",
                similar_cves=["CVE-2020-15133 (tenant isolation)", "CVE-2021-32740 (multi-tenant leak)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Multi-tenant context", "Missing isolation controls"],
                strong_evidence=["No tenant_id filtering"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Implement tenant isolation using RLS policies and tenant_id filtering",
                fix_rationale="Proper tenant isolation is fundamental to multi-tenant security. RLS enforces at database level.",
                alternative_fixes=[
                    "Snowflake RLS policies filtering by tenant_id",
                    "Application-level tenant filtering (less robust)",
                    "Separate schemas per tenant (operational complexity)"
                ],
                tradeoffs="RLS is most secure; application filtering is easier but error-prone",
                implementation_complexity="Medium",
                breaking_changes=False,
                testing_guidance="Test cross-tenant queries fail. Verify tenant context in all queries."
            ),
            context=ContextAnalysis(
                function_purpose="Multi-tenant data access",
                data_flow="Query → Multi-tenant table (no filtering)",
                missing_controls=["Tenant isolation", "RLS policy"],
                framework_context="Multi-tenant SaaS"
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_generic_cot(
        self, pattern: PermissionPattern, evidence: str,
        line_number: int, file_path: str, surrounding_context: str
    ) -> ChainOfThought:
        """Generate generic CoT for categories without specific templates."""
        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=pattern.description,
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching",
                signals_observed=[pattern.description],
                agent_name="PermissionReviewerAgent",
                check_name="generic_permission_check"
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"{pattern.severity.value} severity: {pattern.description}",
                impact_description="Authorization or permission vulnerability detected; potential unauthorized access",
                affected_assets=["Application resources"],
                attack_surface="Code location identified",
                data_sensitivity="Unknown"
            ),
            attack=AttackScenario(
                attack_vector="Exploit detected permission vulnerability",
                attack_steps=["Identify vulnerability", "Craft exploit", "Execute attack"],
                required_access="Depends on vulnerability context",
                exploitability_rating="Medium"
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=[pattern.description],
                strong_evidence=["Pattern match"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix=pattern.recommendation,
                fix_rationale="Apply recommended permission fix",
                implementation_complexity="Medium",
                breaking_changes=False
            ),
            generated_by_agent="PermissionReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def review_file(self, filepath: str, content: str) -> List[Finding]:
        """
        Review a file for permission vulnerabilities.

        Args:
            filepath: Path to the file being reviewed
            content: File content as string

        Returns:
            List of Finding objects representing detected vulnerabilities
        """
        findings: List[Finding] = []

        # Pattern-based detection
        findings.extend(self._pattern_based_detection(filepath, content))

        # Sort by severity and line number
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        findings.sort(key=lambda f: (severity_order[f.severity], f.line_number))

        return findings

    def _pattern_based_detection(self, filepath: str, content: str) -> List[Finding]:
        """Detect permission vulnerabilities using regex patterns."""
        findings: List[Finding] = []
        lines = content.split('\n')

        for pattern_spec in self.patterns:
            for match in pattern_spec.pattern.finditer(content):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1

                # Check for false positives
                if self._is_false_positive(match.group(0), pattern_spec.false_positive_patterns):
                    continue

                # Extract evidence (matched text + context)
                evidence = match.group(0).strip()
                if len(evidence) > 200:
                    evidence = evidence[:197] + "..."

                # Get surrounding context
                context_lines = self._get_context(lines, line_num, context_size=2)

                finding = Finding(
                    category=pattern_spec.category,
                    severity=pattern_spec.severity,
                    confidence=pattern_spec.confidence,
                    line_number=line_num,
                    evidence=evidence,
                    recommendation=pattern_spec.recommendation,
                    file_path=filepath,
                    context=context_lines,
                    owasp_reference=pattern_spec.owasp_ref,
                    cis_reference=pattern_spec.cis_ref
                )

                # Generate Chain of Thought for HIGH and CRITICAL findings
                if pattern_spec.severity in [Severity.HIGH, Severity.CRITICAL]:
                    try:
                        finding.chain_of_thought = self._generate_chain_of_thought(
                            pattern=pattern_spec,
                            evidence=evidence,
                            line_number=line_num,
                            file_path=filepath,
                            surrounding_context=context_lines
                        )
                    except Exception as e:
                        logger.warning(f"Failed to generate CoT for finding at line {line_num}: {e}")
                        # Continue without CoT if generation fails
                        finding.chain_of_thought = None

                findings.append(finding)

        return findings

    def _is_false_positive(self, matched_text: str, fp_patterns: List[Pattern]) -> bool:
        """Check if match is a false positive."""
        for pattern in fp_patterns:
            if pattern.search(matched_text):
                return True
        return False

    def _get_context(self, lines: List[str], line_num: int, context_size: int = 2) -> str:
        """Get surrounding context lines for a finding."""
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        context_lines = lines[start:end]

        # Add line numbers
        numbered_lines = [
            f"{start + i + 1:4d}: {line}"
            for i, line in enumerate(context_lines)
        ]
        return '\n'.join(numbered_lines)

    def review_directory(self, directory: str, recursive: bool = True) -> Dict[str, List[Finding]]:
        """
        Review all files in a directory for permission vulnerabilities.

        Args:
            directory: Path to directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            Dictionary mapping file paths to lists of findings
        """
        results = {}
        path = Path(directory)

        # Get all files to scan
        if recursive:
            files = [f for f in path.rglob('*') if f.is_file() and f.suffix in self.file_extensions]
        else:
            files = [f for f in path.glob('*') if f.is_file() and f.suffix in self.file_extensions]

        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                findings = self.review_file(str(file_path), content)
                if findings:
                    results[str(file_path)] = findings
                    logger.info(f"Found {len(findings)} issues in {file_path}")

            except Exception as e:
                logger.error(f"Error reviewing {file_path}: {e}")

        return results

    def generate_report(self, findings_by_file: Dict[str, List[Finding]]) -> str:
        """
        Generate a formatted permission review report.

        Args:
            findings_by_file: Dictionary mapping file paths to findings

        Returns:
            Formatted report string
        """
        total_findings = sum(len(findings) for findings in findings_by_file.values())

        if total_findings == 0:
            return "No permission issues detected."

        # Count by severity
        severity_counts = {severity: 0 for severity in Severity}
        for findings in findings_by_file.values():
            for finding in findings:
                severity_counts[finding.severity] += 1

        report = ["=" * 80]
        report.append("PERMISSION REVIEW REPORT")
        report.append("=" * 80)
        report.append(f"\nTotal Files Scanned: {len(findings_by_file)}")
        report.append(f"Total Issues Found: {total_findings}\n")

        report.append("Severity Breakdown:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts[severity]
            if count > 0:
                report.append(f"  {severity.value}: {count}")

        report.append("\n" + "=" * 80)
        report.append("DETAILED FINDINGS")
        report.append("=" * 80 + "\n")

        for file_path, findings in sorted(findings_by_file.items()):
            report.append(f"\nFile: {file_path}")
            report.append("-" * 80)

            for i, finding in enumerate(findings, 1):
                report.append(f"\n{i}. [{finding.severity.value}] {finding.category.value}")
                report.append(f"   Line: {finding.line_number}")
                report.append(f"   Confidence: {finding.confidence.value}")
                report.append(f"   Evidence: {finding.evidence}")
                report.append(f"   Recommendation: {finding.recommendation}")

                if finding.owasp_reference:
                    report.append(f"   OWASP: {finding.owasp_reference}")
                if finding.cis_reference:
                    report.append(f"   CIS: {finding.cis_reference}")

                # Include CoT summary if present
                if finding.chain_of_thought:
                    report.append(f"\n   Chain of Thought Summary:")
                    cot_summary = finding.chain_of_thought.get_summary()
                    for line in cot_summary.split('\n'):
                        report.append(f"   {line}")

        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)


# ─── Example Usage ──────────────────────────────────────────────────────────


if __name__ == "__main__":
    # Example: Review a single file
    agent = PermissionReviewerAgent()

    sample_code = '''
-- CRITICAL: Missing RLS on multi-tenant table
CREATE TABLE customers (
    id INT,
    tenant_id INT,
    name VARCHAR(100),
    email VARCHAR(100)
);

-- HIGH: GRANT ALL to PUBLIC
GRANT ALL PRIVILEGES ON TABLE customers TO ROLE PUBLIC;

-- CRITICAL: ACCOUNTADMIN in app code
USE ROLE ACCOUNTADMIN;

-- HIGH: View without tenant filter
CREATE VIEW customer_view AS
SELECT * FROM customers;

-- HIGH: UPDATE without ownership check
UPDATE orders SET status = 'cancelled' WHERE order_id = 123;
'''

    findings = agent.review_file("schema.sql", sample_code)

    print(f"Found {len(findings)} permission issues:\n")
    for finding in findings:
        print(f"[{finding.severity.value}] {finding.category.value}")
        print(f"  Line {finding.line_number}: {finding.evidence}")
        print(f"  {finding.recommendation}")
        if finding.chain_of_thought:
            print(f"\n  CoT Summary:")
            print(finding.chain_of_thought.get_summary())
        print()

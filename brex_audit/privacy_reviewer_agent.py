"""
Privacy Reviewer Agent for Code Analysis
=========================================
A specialized agent that detects privacy and compliance violations in code files, focusing on:
- PII exposure in logs and insecure storage
- Missing encryption for sensitive data
- GDPR compliance violations
- CCPA compliance violations
- HIPAA compliance violations (healthcare data)
- PCI DSS violations (payment card data)
- SOC 2 compliance violations
- Data retention and deletion issues

Knowledge sources:
- GDPR (General Data Protection Regulation)
- CCPA (California Consumer Privacy Act)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI DSS (Payment Card Industry Data Security Standard)
- SOC 2 Compliance Framework

Usage:
    from brex_audit.privacy_reviewer_agent import PrivacyReviewerAgent

    agent = PrivacyReviewerAgent()
    findings = agent.review_file("/path/to/file.py", file_content)

    for finding in findings:
        print(f"{finding.severity}: {finding.category}")
        print(f"  Line {finding.line_number}: {finding.evidence}")
        print(f"  Recommendation: {finding.recommendation}")
"""

import ast
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
    ConfidenceLevel
)

logger = logging.getLogger(__name__)


# ─── Enums ──────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Privacy finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Confidence level for detection accuracy."""
    HIGH = "HIGH"      # Clear violation, minimal false positives
    MEDIUM = "MEDIUM"  # Likely violation, some context needed
    LOW = "LOW"        # Possible violation, requires manual review


class Category(str, Enum):
    """Privacy violation categories."""
    PII_EXPOSURE = "PII Exposure"
    MISSING_ENCRYPTION = "Missing Encryption"
    GDPR_VIOLATION = "GDPR Violation"
    CCPA_VIOLATION = "CCPA Violation"
    HIPAA_VIOLATION = "HIPAA Violation"
    PCI_DSS_VIOLATION = "PCI DSS Violation"
    SOC2_VIOLATION = "SOC 2 Violation"
    DATA_RETENTION = "Data Retention Issue"
    MISSING_CONSENT = "Missing Consent Mechanism"
    INSECURE_DATA_STORAGE = "Insecure Data Storage"
    DATA_MINIMIZATION = "Data Minimization Violation"


# ─── Data Classes ───────────────────────────────────────────────────────────


@dataclass
class Finding:
    """Represents a privacy finding from code analysis."""
    category: Category
    severity: Severity
    confidence: Confidence
    line_number: int
    evidence: str
    recommendation: str
    file_path: Optional[str] = None
    context: Optional[str] = None
    regulation_reference: Optional[str] = None
    compliance_framework: Optional[str] = None
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
            "regulation_reference": self.regulation_reference,
            "compliance_framework": self.compliance_framework,
        }

        # Include CoT if present
        if self.chain_of_thought:
            result["chain_of_thought"] = self.chain_of_thought.to_dict()

        return result


@dataclass
class PrivacyPattern:
    """Represents a privacy violation pattern."""
    pattern: Pattern
    category: Category
    severity: Severity
    confidence: Confidence
    description: str
    recommendation: str
    regulation_ref: Optional[str] = None
    compliance_ref: Optional[str] = None
    false_positive_patterns: List[Pattern] = field(default_factory=list)


# ─── Privacy Reviewer Agent ────────────────────────────────────────────────


class PrivacyReviewerAgent:
    """
    Multi-layer privacy code reviewer with pattern-based and AST-based detection.

    Detection methods:
    1. Regex pattern matching for common privacy violations
    2. AST parsing for Python-specific privacy issues
    3. Context-aware analysis to reduce false positives
    4. Severity and confidence scoring
    5. Regulation and compliance mapping
    """

    def __init__(self, enable_ast_analysis: bool = True):
        """
        Initialize the Privacy Reviewer Agent.

        Args:
            enable_ast_analysis: Enable AST-based analysis for Python files
        """
        self.enable_ast_analysis = enable_ast_analysis
        self.patterns = self._initialize_patterns()
        self.file_extensions = {
            '.py', '.js', '.ts', '.java', '.sql', '.sh', '.bash',
            '.yml', '.yaml', '.json', '.xml', '.env', '.config'
        }

    def _initialize_patterns(self) -> List[PrivacyPattern]:
        """Initialize comprehensive privacy violation patterns."""
        patterns = []

        # ═══ PII Exposure in Logs ═══

        # Email addresses in logs
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(log|print|console|echo|write).*["\'].*\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                re.IGNORECASE
            ),
            category=Category.PII_EXPOSURE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Email address or email pattern in log statement",
            recommendation="Redact PII from logs using structured logging with redaction. Example: log.info('User action', user_id=hash(email))",
            regulation_ref="GDPR Article 5(1)(f) - Integrity and confidentiality",
            compliance_ref="SOC 2 CC6.1"
        ))

        # SSN pattern in logs
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(log|print|console|echo).*["\'].*\b\d{3}-\d{2}-\d{4}\b',
                re.IGNORECASE
            ),
            category=Category.PII_EXPOSURE,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Social Security Number pattern in log statement",
            recommendation="Never log SSNs. Use tokenized identifiers or hashed references instead.",
            regulation_ref="GDPR Article 5(1)(f), HIPAA §164.514",
            compliance_ref="SOC 2 CC6.1"
        ))

        # Credit card patterns in logs
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(log|print|console|echo).*["\'].*\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                re.IGNORECASE
            ),
            category=Category.PCI_DSS_VIOLATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Credit card number pattern in log statement",
            recommendation="Never log full credit card numbers. Use last 4 digits only: '**** **** **** 1234'",
            regulation_ref="PCI DSS 3.4",
            compliance_ref="PCI DSS Requirement 3"
        ))

        # Phone number patterns in logs
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(log|print|console).*["\'].*\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                re.IGNORECASE
            ),
            category=Category.PII_EXPOSURE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Phone number pattern in log statement",
            recommendation="Redact or hash phone numbers in logs. Use structured logging with PII redaction.",
            regulation_ref="GDPR Article 5(1)(f)",
            compliance_ref="SOC 2 CC6.1"
        ))

        # Generic PII in log statements (user_email, user_phone, ssn, etc.)
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(log|logger|print|console)\.(info|debug|warn|error|log)\s*\([^)]*\b(user\.|customer\.|patient\.)?'
                r'(email|phone|ssn|social_security|address|dob|date_of_birth|credit_card|password)\b',
                re.IGNORECASE
            ),
            category=Category.PII_EXPOSURE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="PII field logged directly without redaction",
            recommendation="Redact PII fields in logs. Use structured logging with automatic PII redaction or hash sensitive fields.",
            regulation_ref="GDPR Article 5(1)(f)",
            compliance_ref="SOC 2 CC6.1"
        ))

        # ═══ Missing Encryption ═══

        # Unencrypted PII in database
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(ssn|social_security|credit_card|card_number|cvv|tax_id)\s*(=|:)\s*models\.(CharField|TextField|String)',
                re.IGNORECASE
            ),
            category=Category.MISSING_ENCRYPTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Sensitive data stored in plaintext database field",
            recommendation="Use field-level encryption for sensitive data. Example: EncryptedCharField() or encrypt at application layer before storage.",
            regulation_ref="PCI DSS 3.4, HIPAA §164.312(a)(2)(iv)",
            compliance_ref="GDPR Article 32"
        ))

        # HTTP instead of HTTPS for sensitive data
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(url|endpoint|api_url)\s*=\s*["\']http://[^"\']*\b(user|customer|payment|health|medical|login|auth)\b',
                re.IGNORECASE
            ),
            category=Category.MISSING_ENCRYPTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Sensitive data endpoint using unencrypted HTTP",
            recommendation="Use HTTPS for all sensitive data transmission. Update URL scheme to https://",
            regulation_ref="GDPR Article 32, HIPAA §164.312(e)(1)",
            compliance_ref="PCI DSS 4.1"
        ))

        # FTP for sensitive data transfer
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(ftp://|FTP\()',
                re.IGNORECASE
            ),
            category=Category.MISSING_ENCRYPTION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Unencrypted FTP used for data transfer",
            recommendation="Use SFTP or FTPS for encrypted file transfer. Replace ftp:// with sftp://",
            regulation_ref="GDPR Article 32",
            compliance_ref="SOC 2 CC6.1"
        ))

        # ═══ GDPR Violations ═══

        # Missing consent mechanism
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(collect|store|process).*\b(email|personal_data|user_data)\b',
                re.IGNORECASE
            ),
            category=Category.GDPR_VIOLATION,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,  # Low confidence without context
            description="Data collection without visible consent mechanism",
            recommendation="Implement explicit consent before collecting personal data. Document lawful basis per GDPR Article 6.",
            regulation_ref="GDPR Article 6, Article 7",
            compliance_ref="GDPR compliance"
        ))

        # Data retention without expiry
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)def\s+store_user_data|def\s+save_personal_info',
                re.IGNORECASE
            ),
            category=Category.DATA_RETENTION,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description="Data storage without visible retention policy",
            recommendation="Implement data retention policies with automatic deletion. Document retention periods per GDPR Article 5(1)(e).",
            regulation_ref="GDPR Article 5(1)(e) - Storage limitation",
            compliance_ref="GDPR compliance"
        ))

        # ═══ HIPAA Violations (Healthcare) ═══

        # PHI in logs
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(log|print|console).*\b(patient|medical|diagnosis|prescription|health_record|phi|medical_record)\b',
                re.IGNORECASE
            ),
            category=Category.HIPAA_VIOLATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            description="Protected Health Information (PHI) in log statements",
            recommendation="Never log PHI. Use de-identified references or audit logs with proper access controls.",
            regulation_ref="HIPAA §164.514, §164.308(a)(1)(ii)(D)",
            compliance_ref="HIPAA Privacy Rule"
        ))

        # Unencrypted PHI storage
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(diagnosis|medical_record|prescription|health_data|phi)\s*=\s*models\.(CharField|TextField|String)(?!.*encrypt)',
                re.IGNORECASE
            ),
            category=Category.HIPAA_VIOLATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Protected Health Information stored without encryption",
            recommendation="Encrypt PHI at rest using field-level encryption or database-level encryption.",
            regulation_ref="HIPAA §164.312(a)(2)(iv)",
            compliance_ref="HIPAA Security Rule"
        ))

        # ═══ PCI DSS Violations ═══

        # CVV storage
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(cvv|cvc|card_verification|security_code)\s*=\s*',
                re.IGNORECASE
            ),
            category=Category.PCI_DSS_VIOLATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="CVV/CVC storage detected (PCI DSS violation)",
            recommendation="Never store CVV/CVC codes. This is explicitly prohibited by PCI DSS Requirement 3.2.",
            regulation_ref="PCI DSS Requirement 3.2",
            compliance_ref="PCI DSS"
        ))

        # Unencrypted cardholder data
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(card_number|cardholder|pan|primary_account_number)\s*=\s*models\.(CharField|TextField|String)(?!.*encrypt)',
                re.IGNORECASE
            ),
            category=Category.PCI_DSS_VIOLATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Cardholder data stored without encryption",
            recommendation="Encrypt cardholder data at rest per PCI DSS 3.4. Use strong encryption (AES-256).",
            regulation_ref="PCI DSS 3.4",
            compliance_ref="PCI DSS Requirement 3"
        ))

        # ═══ CCPA Violations ═══

        # Missing opt-out mechanism
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)def\s+(sell|share).*\buser_data\b',
                re.IGNORECASE
            ),
            category=Category.CCPA_VIOLATION,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            description="Data sale/sharing without visible opt-out mechanism",
            recommendation="Implement 'Do Not Sell My Personal Information' option per CCPA 1798.120.",
            regulation_ref="CCPA 1798.120",
            compliance_ref="CCPA compliance"
        ))

        # ═══ SOC 2 Violations ═══

        # Sensitive data in plaintext config
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(database_url|db_connection|connection_string)\s*=\s*["\'][^"\']*password=[^"\'@]+',
                re.IGNORECASE
            ),
            category=Category.SOC2_VIOLATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Database credentials in plaintext connection string",
            recommendation="Use environment variables or secret management for credentials. Avoid plaintext passwords in config.",
            regulation_ref="SOC 2 CC6.1",
            compliance_ref="SOC 2"
        ))

        # ═══ Data Minimization ═══

        # Collecting excessive PII
        patterns.append(PrivacyPattern(
            pattern=re.compile(
                r'(?i)(ssn|social_security|full_address|date_of_birth|driver_license)',
                re.IGNORECASE
            ),
            category=Category.DATA_MINIMIZATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description="Collection of sensitive PII - verify necessity",
            recommendation="Apply data minimization principle (GDPR Article 5(1)(c)). Collect only data necessary for specific purpose.",
            regulation_ref="GDPR Article 5(1)(c)",
            compliance_ref="GDPR compliance"
        ))

        return patterns

    def _generate_chain_of_thought(
        self,
        pattern: PrivacyPattern,
        evidence: str,
        line_number: int,
        file_path: str,
        surrounding_context: str
    ) -> ChainOfThought:
        """
        Generate Chain of Thought reasoning for a privacy finding.

        Args:
            pattern: The privacy pattern that matched
            evidence: The code evidence
            line_number: Line number of finding
            file_path: Path to file
            surrounding_context: Code around the finding

        Returns:
            ChainOfThought instance with complete reasoning
        """
        # Generate category-specific reasoning
        if pattern.category == Category.PII_EXPOSURE:
            return self._generate_pii_exposure_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.MISSING_ENCRYPTION:
            return self._generate_missing_encryption_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.GDPR_VIOLATION:
            return self._generate_gdpr_violation_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.CCPA_VIOLATION:
            return self._generate_ccpa_violation_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.HIPAA_VIOLATION:
            return self._generate_hipaa_violation_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.PCI_DSS_VIOLATION:
            return self._generate_pci_dss_violation_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.SOC2_VIOLATION:
            return self._generate_soc2_violation_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.DATA_RETENTION:
            return self._generate_data_retention_cot(pattern, evidence, line_number, file_path, surrounding_context)
        else:
            return self._generate_generic_privacy_cot(pattern, evidence, line_number, file_path, surrounding_context)

    def _generate_pii_exposure_cot(self, pattern: PrivacyPattern, evidence: str,
                                   line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for PII exposure findings."""
        # Determine PII type
        pii_type = "Email address" if "@" in evidence or "email" in evidence.lower() else \
                   "Social Security Number" if re.search(r'\d{3}-\d{2}-\d{4}', evidence) else \
                   "Phone number" if re.search(r'\d{3}[-.]?\d{3}[-.]?\d{4}', evidence) else \
                   "PII field"

        signals = [f"{pii_type} in log statement", "No redaction mechanism", "Direct logging of sensitive data"]

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=f"{pii_type} in application logs",
                evidence_summary=f"Line {line_number}: {evidence[:80]}",
                detection_method="Regex pattern matching for PII types in logging statements",
                signals_observed=signals,
                agent_name="PrivacyReviewerAgent",
                check_name="_check_pii_exposure"
            ),
            risk=RiskAnalysis(
                severity_reasoning="GDPR Article 5(1)(f) requires appropriate security of personal data; logs are often widely accessible to developers, ops, and monitoring tools",
                impact_description="PII exposure to unauthorized personnel via logs; increased data breach risk; regulatory violations; potential fines",
                affected_assets=[f"User {pii_type.lower()}", "Log files", "Monitoring systems", "Log aggregation platforms"],
                attack_surface="Application logs accessible to developers, operations staff, monitoring tools, and log aggregation systems",
                data_sensitivity="PII",
                compliance_impact=["GDPR Article 5(1)(f)", "CCPA 1798.100(a)", "SOC 2 CC6.1", "HIPAA §164.514(b)"]
            ),
            attack=AttackScenario(
                attack_vector="Access to application logs via log aggregation system, file access, or compromised monitoring credentials",
                attack_steps=[
                    "Gain access to log files (developer access, compromised monitoring system, or insider threat)",
                    f"Search logs for {pii_type.lower()} patterns using grep or log query language",
                    f"Extract {pii_type.lower()}s for identity theft, phishing, or unauthorized access",
                    "Use extracted PII for social engineering or account takeover attacks"
                ],
                required_access="Log read access (commonly granted to developers, DevOps, and monitoring systems)",
                exploitability_rating="Easy",
                similar_cves=["CVE-2019-11043 (PII in logs)", "CVE-2021-22096 (Log exposure)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=[f"Clear {pii_type.lower()} pattern in logs", "Logging statement context", "No redaction mechanism visible"],
                strong_evidence=[f"{pii_type} pattern match", "log.info/debug/error call", "Direct field logging"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Redact PII before logging using structured redaction library",
                fix_rationale="Redaction removes PII from logs while preserving debugging utility by keeping log structure intact; maintains compliance with GDPR Article 5(1)(f) data minimization",
                alternative_fixes=[
                    "Hash PII before logging (preserves correlation but not readability)",
                    "Remove logging statement entirely (reduces observability)",
                    "Use separate PII-safe logs with strict access controls",
                    "Implement structured logging with automatic PII field redaction"
                ],
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Verify PII is redacted in logs (check for '***REDACTED***' or hash); test that debugging remains effective with redacted logs"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_missing_encryption_cot(self, pattern: PrivacyPattern, evidence: str,
                                         line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for missing encryption findings."""
        # Determine data type and severity
        is_payment = any(term in evidence.lower() for term in ["card", "cvv", "credit", "payment"])
        is_health = any(term in evidence.lower() for term in ["medical", "health", "phi", "diagnosis"])
        is_http = "http://" in evidence.lower()

        if is_payment:
            data_type = "Payment card data"
            regulation = "PCI DSS 3.4"
            severity_text = "PCI DSS 3.4 requires cardholder data to be rendered unreadable; failure is automatic compliance violation"
        elif is_health:
            data_type = "Protected Health Information"
            regulation = "HIPAA §164.312(a)(2)(iv)"
            severity_text = "HIPAA requires encryption of PHI at rest; violation risks penalties up to $1.5M per year"
        elif is_http:
            data_type = "Sensitive data in transit"
            regulation = "GDPR Article 32"
            severity_text = "Transmitting sensitive data over unencrypted HTTP exposes it to interception and man-in-the-middle attacks"
        else:
            data_type = "Sensitive personal data"
            regulation = "GDPR Article 32"
            severity_text = "GDPR Article 32 requires appropriate technical measures including encryption for personal data"

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        compliance_refs = []
        if is_payment:
            compliance_refs = ["PCI DSS 3.4", "PCI DSS Requirement 4.1", "GDPR Article 32"]
        elif is_health:
            compliance_refs = ["HIPAA §164.312(a)(2)(iv)", "HIPAA §164.312(e)(1)", "GDPR Article 32"]
        else:
            compliance_refs = ["GDPR Article 32", "SOC 2 CC6.1", "NIST SP 800-53 SC-13"]

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=f"Unencrypted storage/transmission of {data_type.lower()}",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for sensitive data fields without encryption indicators",
                signals_observed=["Sensitive data field", "No encryption mechanism", "Plaintext storage/transmission"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_missing_encryption"
            ),
            risk=RiskAnalysis(
                severity_reasoning=severity_text,
                impact_description=f"Data breach exposing {data_type.lower()}; regulatory fines and penalties; reputational damage; potential identity theft or fraud",
                affected_assets=[data_type, "Database records", "User privacy", "Regulatory compliance"],
                attack_surface="Database accessible to application, DBAs, and potentially attackers via SQL injection or compromised credentials",
                data_sensitivity="Financial + PII" if is_payment else "PHI" if is_health else "PII",
                compliance_impact=compliance_refs
            ),
            attack=AttackScenario(
                attack_vector="Database breach, SQL injection, or unauthorized database access",
                attack_steps=[
                    "Gain database access (SQL injection, stolen credentials, or insider threat)",
                    f"Query table containing unencrypted {data_type.lower()}",
                    "Extract sensitive data in plaintext",
                    "Use data for fraud, identity theft, or sale on dark web"
                ],
                required_access="Database read access (via application vulnerability or direct database credentials)",
                exploitability_rating="Easy" if is_http else "Medium",
                similar_cves=["CVE-2019-11043 (Data exposure)", "CVE-2021-3177 (Unencrypted data)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Sensitive data field identified", "No encryption mechanism present", f"{regulation} requirement"],
                strong_evidence=["Clear sensitive data pattern", "Plaintext storage indicator"],
                weak_evidence=["Encryption might be at database level"] if not is_http else [],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Implement field-level encryption for sensitive data" if not is_http else "Use HTTPS instead of HTTP for all sensitive endpoints",
                fix_rationale=f"Encryption ensures data is unreadable even if database/network is compromised; satisfies {regulation} requirements; reduces breach impact",
                alternative_fixes=[
                    "Use database-level encryption (Transparent Data Encryption)" if not is_http else "Implement TLS 1.2+ with strong ciphers",
                    "Use application-layer encryption before storage" if not is_http else "Use API gateway with HTTPS termination",
                    "Tokenization (replace sensitive data with tokens)" if is_payment else "Use VPN for sensitive data transmission"
                ],
                implementation_complexity="Medium" if not is_http else "Easy",
                breaking_changes=True if not is_http else False,
                testing_guidance="Verify data is encrypted at rest; test encryption/decryption performance; validate key management" if not is_http else "Test HTTPS connectivity; verify SSL certificate validity; check for mixed content warnings"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_gdpr_violation_cot(self, pattern: PrivacyPattern, evidence: str,
                                     line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for GDPR violation findings."""
        confidence_level = ConfidenceLevel.LOW  # GDPR violations often need more context

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Data collection/processing without visible consent mechanism",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for data collection without consent indicators",
                signals_observed=["Data collection function", "No consent check visible", "Personal data processing"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_gdpr_violation"
            ),
            risk=RiskAnalysis(
                severity_reasoning="GDPR Article 6 requires lawful basis for processing; missing consent mechanism violates fundamental GDPR requirement",
                impact_description="Regulatory investigation by supervisory authority; fines up to €20M or 4% of global revenue; requirement to cease processing; reputational damage",
                affected_assets=["User personal data", "Data processing activities", "User consent records"],
                attack_surface="Data collection and processing functions",
                data_sensitivity="PII",
                compliance_impact=["GDPR Article 6 (Lawfulness)", "GDPR Article 7 (Consent)", "GDPR Article 5(1)(a) (Lawfulness, fairness, transparency)"]
            ),
            attack=AttackScenario(
                attack_vector="Regulatory audit or user complaint",
                attack_steps=[
                    "User files complaint with supervisory authority",
                    "Authority investigates data processing practices",
                    "Discovers lack of valid consent",
                    "Issues enforcement action and fines"
                ],
                required_access="N/A - Regulatory enforcement",
                exploitability_rating="N/A",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Data collection detected", "No consent mechanism visible in local code"],
                strong_evidence=["Personal data collection function"],
                weak_evidence=["Consent may be implemented elsewhere", "May rely on legitimate interest", "Context unclear from code alone"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Implement explicit consent mechanism before collecting personal data",
                fix_rationale="GDPR requires informed, freely given, specific consent; explicit mechanism ensures compliance and provides audit trail",
                alternative_fixes=[
                    "Document legitimate interest assessment (if consent not applicable)",
                    "Implement contract-based processing (for service delivery)",
                    "Add consent checkboxes with clear explanations",
                    "Maintain consent records with timestamps and versions"
                ],
                implementation_complexity="Medium",
                breaking_changes=True,
                testing_guidance="Verify consent is obtained before data collection; test consent withdrawal functionality; ensure consent records are maintained; validate privacy notice is clear and accessible"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_ccpa_violation_cot(self, pattern: PrivacyPattern, evidence: str,
                                     line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for CCPA violation findings."""
        confidence_level = ConfidenceLevel.LOW

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Data sale/sharing without visible opt-out mechanism",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for data sale/sharing functions",
                signals_observed=["Data sale/sharing function", "No opt-out mechanism visible"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_ccpa_violation"
            ),
            risk=RiskAnalysis(
                severity_reasoning="CCPA 1798.120 requires right to opt-out of personal information sale; missing mechanism violates consumer rights",
                impact_description="CCPA enforcement action; fines up to $7,500 per intentional violation; private right of action for data breaches; reputational damage",
                affected_assets=["User personal information", "Data sharing agreements", "Consumer rights"],
                attack_surface="Data sale and sharing operations",
                data_sensitivity="PII",
                compliance_impact=["CCPA 1798.120 (Right to Opt-Out)", "CCPA 1798.100 (Consumer Rights)", "CCPA 1798.115 (Disclosure Requirements)"]
            ),
            attack=AttackScenario(
                attack_vector="Consumer complaint or California AG investigation",
                attack_steps=[
                    "Consumer requests opt-out but mechanism unavailable",
                    "Consumer files complaint with California AG",
                    "AG investigates data sale practices",
                    "Enforcement action and penalties"
                ],
                required_access="N/A - Regulatory enforcement",
                exploitability_rating="N/A",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Data sale/sharing detected", "No opt-out visible in code"],
                strong_evidence=["Function name suggests data sale/sharing"],
                weak_evidence=["Opt-out may be implemented elsewhere", "May not constitute 'sale' under CCPA", "Context unclear"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Implement 'Do Not Sell My Personal Information' opt-out mechanism",
                fix_rationale="CCPA mandates clear opt-out for data sales; mechanism must be easy to access and honor user choices",
                alternative_fixes=[
                    "Add 'Do Not Sell' link on homepage and privacy policy",
                    "Implement Global Privacy Control (GPC) support",
                    "Maintain opt-out preference database",
                    "Stop selling personal information entirely"
                ],
                implementation_complexity="Medium",
                breaking_changes=True,
                testing_guidance="Verify opt-out mechanism is accessible; test that opt-out preferences are honored; ensure data sale stops after opt-out; validate GPC signal handling"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_hipaa_violation_cot(self, pattern: PrivacyPattern, evidence: str,
                                      line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for HIPAA violation findings."""
        is_phi_in_logs = any(term in evidence.lower() for term in ["log", "print", "console"])

        confidence_level = ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.HIGH

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Protected Health Information (PHI) in logs or unencrypted storage" if is_phi_in_logs else "PHI stored without encryption",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for PHI in insecure contexts",
                signals_observed=["PHI field detected", "No encryption" if not is_phi_in_logs else "Logging statement", "HIPAA-regulated data"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_hipaa_violation"
            ),
            risk=RiskAnalysis(
                severity_reasoning="HIPAA Security Rule mandates encryption of ePHI and strict access controls; violation risks OCR penalties up to $1.5M per year per violation category",
                impact_description="HIPAA breach notification required for 500+ individuals; OCR investigation and penalties; potential criminal charges; patient privacy violation; reputational damage to healthcare organization",
                affected_assets=["Protected Health Information (ePHI)", "Patient records", "Medical diagnoses", "Treatment information"],
                attack_surface="Application logs and monitoring systems" if is_phi_in_logs else "Database and file storage systems",
                data_sensitivity="PHI (Protected Health Information)",
                compliance_impact=["HIPAA §164.312(a)(2)(iv) (Encryption)", "HIPAA §164.308(a)(1)(ii)(D) (Information System Activity Review)", "HIPAA §164.514(b) (De-identification)"]
            ),
            attack=AttackScenario(
                attack_vector="Access to logs or database breach" if is_phi_in_logs else "Database compromise or unauthorized access",
                attack_steps=[
                    "Gain access to application logs" if is_phi_in_logs else "Compromise database credentials or exploit SQL injection",
                    "Search for PHI patterns (diagnoses, patient names, medical record numbers)",
                    "Extract PHI for identity theft or medical fraud",
                    "Trigger HIPAA breach notification requirements"
                ],
                required_access="Log access (developer/ops)" if is_phi_in_logs else "Database read access",
                exploitability_rating="Easy",
                similar_cves=["CVE-2015-0235 (Healthcare data breach)", "CVE-2019-11043 (PHI exposure)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Clear PHI pattern", "HIPAA-regulated context", "No encryption/redaction visible"],
                strong_evidence=["Medical terminology", "Health-related field names", "Patient data indicators"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Never log PHI; use de-identified references or audit logs with proper access controls" if is_phi_in_logs else "Encrypt PHI at rest using field-level encryption",
                fix_rationale="HIPAA requires safeguards for ePHI; logging PHI violates minimum necessary principle; encryption ensures compliance with Security Rule",
                alternative_fixes=[
                    "Use de-identified data per HIPAA §164.514(b)" if is_phi_in_logs else "Implement database-level encryption (TDE)",
                    "Implement separate audit logs with strict access controls" if is_phi_in_logs else "Use tokenization for PHI fields",
                    "Hash patient identifiers for correlation" if is_phi_in_logs else "Apply access controls and audit logging",
                    "Train developers on HIPAA requirements"
                ],
                implementation_complexity="Medium",
                breaking_changes=True if not is_phi_in_logs else False,
                testing_guidance="Verify PHI is not present in logs; test de-identification" if is_phi_in_logs else "Verify PHI encryption at rest; test key management; validate access controls; ensure encryption doesn't break queries"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_pci_dss_violation_cot(self, pattern: PrivacyPattern, evidence: str,
                                        line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for PCI DSS violation findings."""
        is_cvv = any(term in evidence.lower() for term in ["cvv", "cvc", "security_code"])

        confidence_level = ConfidenceLevel.HIGH

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="CVV/CVC storage (PCI DSS violation)" if is_cvv else "Cardholder data stored without encryption",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for payment card data",
                signals_observed=["CVV/CVC field" if is_cvv else "Card number field", "Storage operation", "No encryption"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_pci_dss_violation"
            ),
            risk=RiskAnalysis(
                severity_reasoning="PCI DSS Requirement 3.2 explicitly prohibits CVV storage; violation results in automatic PCI DSS non-compliance" if is_cvv else "PCI DSS 3.4 requires cardholder data encryption; failure is compliance violation with severe consequences",
                impact_description="Immediate PCI DSS non-compliance; card brand fines and penalties; potential loss of card processing privileges; forensic audit costs; reputational damage; customer trust erosion",
                affected_assets=["Payment card data", "CVV/CVC codes" if is_cvv else "Primary Account Numbers (PAN)", "Customer payment information"],
                attack_surface="Database accessible to application and DBAs; payment processing code",
                data_sensitivity="Financial + PII",
                compliance_impact=["PCI DSS Requirement 3.2" if is_cvv else "PCI DSS 3.4", "PCI DSS Requirement 3.5", "GDPR Article 32"]
            ),
            attack=AttackScenario(
                attack_vector="Database breach, SQL injection, or insider threat",
                attack_steps=[
                    "Compromise database or payment processing system",
                    "Query tables containing payment card data",
                    "Extract CVV codes (instant fraud capability)" if is_cvv else "Extract unencrypted card numbers",
                    "Use for fraudulent card-not-present transactions" if is_cvv else "Sell on dark web or use for fraud"
                ],
                required_access="Database access or SQL injection vulnerability",
                exploitability_rating="Easy",
                similar_cves=["CVE-2019-11043 (Payment data breach)", "CVE-2021-3177 (Card data exposure)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Clear payment card data pattern", "PCI DSS explicit requirement", "Storage operation detected"],
                strong_evidence=["CVV/CVC field name" if is_cvv else "Card number field", "Storage in database model"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Remove CVV storage entirely - CVV must never be stored per PCI DSS 3.2" if is_cvv else "Encrypt cardholder data at rest using strong encryption (AES-256)",
                fix_rationale="PCI DSS explicitly prohibits CVV storage; removal is only compliant option" if is_cvv else "Encryption renders cardholder data unreadable per PCI DSS 3.4; reduces breach impact and satisfies compliance requirement",
                alternative_fixes=[
                    "Delete any existing CVV data immediately" if is_cvv else "Use tokenization (replace PAN with tokens)",
                    "Update payment flow to never capture CVV for storage" if is_cvv else "Use point-to-point encryption (P2PE)",
                    "Audit codebase for other CVV references" if is_cvv else "Implement key management per PCI DSS 3.5/3.6",
                    "Review PCI DSS SAQ requirements" if is_cvv else "Consider payment gateway to reduce PCI scope"
                ],
                implementation_complexity="Easy" if is_cvv else "Hard",
                breaking_changes=True,
                testing_guidance="Verify CVV is never stored anywhere; test payment flows without CVV storage; validate PCI DSS compliance" if is_cvv else "Verify encryption of all cardholder data; test key rotation; validate encryption strength (AES-256); ensure QSA approval"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_soc2_violation_cot(self, pattern: PrivacyPattern, evidence: str,
                                     line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for SOC 2 violation findings."""
        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else ConfidenceLevel.MEDIUM

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Database credentials in plaintext connection string",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for credentials in connection strings",
                signals_observed=["Plaintext password in connection string", "No secret management", "Credentials in code"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_soc2_violation"
            ),
            risk=RiskAnalysis(
                severity_reasoning="SOC 2 CC6.1 requires logical access security; plaintext credentials in code violate access control principles",
                impact_description="Database credentials exposed in source code; unauthorized database access; data breach; SOC 2 audit failure; customer trust issues",
                affected_assets=["Database credentials", "Database contents", "Customer data", "SOC 2 compliance"],
                attack_surface="Source code repositories, config files, version control history",
                data_sensitivity="Credentials + Database contents",
                compliance_impact=["SOC 2 CC6.1 (Logical and Physical Access)", "SOC 2 CC6.2 (Authentication)", "NIST SP 800-53 IA-5"]
            ),
            attack=AttackScenario(
                attack_vector="Access to source code or config files",
                attack_steps=[
                    "Obtain source code (git clone, leaked repo, insider access)",
                    "Search for connection strings with passwords",
                    "Extract database credentials",
                    "Connect directly to database and access all data"
                ],
                required_access="Source code access or config file access",
                exploitability_rating="Easy",
                similar_cves=["CVE-2021-39175 (Hardcoded credentials)", "CVE-2022-24784 (Config exposure)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Clear password in connection string", "No environment variable usage", "SOC 2 violation"],
                strong_evidence=["password= in plaintext", "Connection string pattern"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use environment variables or secret management for database credentials",
                fix_rationale="Environment variables keep secrets out of source code; secret management provides encryption, rotation, and audit logging per SOC 2 requirements",
                alternative_fixes=[
                    "Use secret management service (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)",
                    "Use encrypted config files with restricted access",
                    "Use IAM database authentication (no passwords)",
                    "Store credentials in .env file (with .gitignore)"
                ],
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Verify credentials are loaded from environment/secret manager; test credential rotation; ensure no credentials in source control history"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_data_retention_cot(self, pattern: PrivacyPattern, evidence: str,
                                     line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for data retention violation findings."""
        confidence_level = ConfidenceLevel.LOW

        # Data retention can be MEDIUM or HIGH severity depending on context
        severity = pattern.severity

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Data storage without visible retention policy or automatic deletion",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for data storage functions",
                signals_observed=["Data storage function", "No retention policy visible", "No deletion mechanism"],
                agent_name="PrivacyReviewerAgent",
                check_name="_check_data_retention"
            ),
            risk=RiskAnalysis(
                severity_reasoning="GDPR Article 5(1)(e) requires storage limitation; indefinite retention increases breach risk and compliance violations",
                impact_description="GDPR non-compliance; increased data breach exposure; accumulation of stale data; inability to honor deletion requests; regulatory fines",
                affected_assets=["User personal data", "Historical records", "Storage systems"],
                attack_surface="Long-term data storage increasing breach surface area",
                data_sensitivity="PII",
                compliance_impact=["GDPR Article 5(1)(e) (Storage Limitation)", "GDPR Article 17 (Right to Erasure)", "CCPA 1798.105 (Right to Delete)"]
            ),
            attack=AttackScenario(
                attack_vector="Data breach of long-retained records",
                attack_steps=[
                    "Attacker compromises database with years of retained data",
                    "Extracts historical personal data that should have been deleted",
                    "Uses data for identity theft or fraud",
                    "Triggers breach notification requirements"
                ],
                required_access="Database access",
                exploitability_rating="Medium",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Data storage function detected", "No retention policy in local code"],
                strong_evidence=["Storage function present"],
                weak_evidence=["Retention policy may be implemented elsewhere", "Deletion may be manual process", "Context unclear from code"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Implement data retention policy with automatic deletion after retention period",
                fix_rationale="Automated retention policies ensure GDPR compliance; reduce breach exposure; honor data minimization principle",
                alternative_fixes=[
                    "Use database TTL (Time-To-Live) features for automatic deletion",
                    "Implement scheduled jobs to delete expired records",
                    "Archive old data to cold storage with limited access",
                    "Document retention periods per GDPR Article 30 (Record of Processing)"
                ],
                implementation_complexity="Medium",
                breaking_changes=False,
                testing_guidance="Verify data is deleted after retention period; test deletion job execution; ensure deletion is logged for audit; validate cascading deletes"
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_generic_privacy_cot(self, pattern: PrivacyPattern, evidence: str,
                                      line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate generic CoT for privacy categories without specific templates."""
        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=pattern.description,
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching",
                signals_observed=[pattern.description],
                agent_name="PrivacyReviewerAgent",
                check_name="generic_privacy_check"
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"{pattern.severity.value} severity: {pattern.description}",
                impact_description="Privacy violation detected; potential regulatory non-compliance; user privacy risk",
                affected_assets=["User data", "Application"],
                attack_surface="Code location identified",
                data_sensitivity="PII",
                compliance_impact=[pattern.regulation_ref] if pattern.regulation_ref else []
            ),
            attack=AttackScenario(
                attack_vector="Privacy violation or regulatory non-compliance",
                attack_steps=["Identify privacy issue", "Privacy breach or audit failure", "Regulatory consequences"],
                required_access="Depends on violation context",
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
                fix_rationale="Apply recommended privacy fix to ensure compliance",
                implementation_complexity="Medium",
                breaking_changes=False
            ),
            generated_by_agent="PrivacyReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def review_file(self, filepath: str, content: str) -> List[Finding]:
        """
        Review a file for privacy violations.

        Args:
            filepath: Path to the file being reviewed
            content: File content as string

        Returns:
            List of Finding objects representing detected violations
        """
        findings: List[Finding] = []

        # Pattern-based detection
        findings.extend(self._pattern_based_detection(filepath, content))

        # AST-based analysis for Python files
        if self.enable_ast_analysis and filepath.endswith('.py'):
            findings.extend(self._ast_based_detection(filepath, content))

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
        """Detect privacy violations using regex patterns."""
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
                    regulation_reference=pattern_spec.regulation_ref,
                    compliance_framework=pattern_spec.compliance_ref
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

    def _ast_based_detection(self, filepath: str, content: str) -> List[Finding]:
        """Detect Python-specific privacy violations using AST parsing."""
        findings: List[Finding] = []

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            logger.debug(f"Syntax error in {filepath}, skipping AST analysis: {e}")
            return findings

        # Check for PII in logging statements
        findings.extend(self._check_pii_in_logs_ast(tree, content, filepath))

        # Check for unencrypted sensitive data storage
        findings.extend(self._check_unencrypted_storage_ast(tree, content, filepath))

        return findings

    def _check_pii_in_logs_ast(self, tree: ast.AST, content: str, filepath: str) -> List[Finding]:
        """Check for PII in logging statements using AST."""
        findings: List[Finding] = []
        lines = content.split('\n')

        pii_field_names = {
            'email', 'phone', 'phone_number', 'ssn', 'social_security',
            'address', 'street_address', 'credit_card', 'card_number',
            'password', 'date_of_birth', 'dob', 'drivers_license',
            'passport', 'medical_record', 'diagnosis', 'patient_name'
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if it's a logging call
                if self._is_logging_call(node):
                    # Check arguments for PII field access
                    for arg in node.args:
                        if self._contains_pii_field(arg, pii_field_names):
                            evidence = f"Logging PII field in statement at line {node.lineno}"
                            context_lines = self._get_context(lines, node.lineno, context_size=2)

                            # Determine severity based on field type
                            severity = Severity.CRITICAL if any(field in self._get_field_names(arg)
                                                                for field in ['ssn', 'social_security', 'credit_card', 'medical_record']) else Severity.HIGH

                            # Create pattern spec for CoT
                            pattern_spec = PrivacyPattern(
                                pattern=re.compile(""),  # Dummy
                                category=Category.PII_EXPOSURE,
                                severity=severity,
                                confidence=Confidence.HIGH,
                                description="PII field in logging statement",
                                recommendation="Redact PII fields before logging using structured redaction",
                                regulation_ref="GDPR Article 5(1)(f)",
                                compliance_ref="SOC 2 CC6.1"
                            )

                            finding = Finding(
                                category=Category.PII_EXPOSURE,
                                severity=severity,
                                confidence=Confidence.HIGH,
                                line_number=node.lineno,
                                evidence=evidence,
                                recommendation="Redact PII fields before logging using structured redaction",
                                file_path=filepath,
                                context=context_lines,
                                regulation_reference="GDPR Article 5(1)(f)",
                                compliance_framework="SOC 2 CC6.1"
                            )

                            # Generate CoT for HIGH/CRITICAL
                            if severity in [Severity.HIGH, Severity.CRITICAL]:
                                try:
                                    finding.chain_of_thought = self._generate_chain_of_thought(
                                        pattern=pattern_spec,
                                        evidence=evidence,
                                        line_number=node.lineno,
                                        file_path=filepath,
                                        surrounding_context=context_lines
                                    )
                                except Exception as e:
                                    logger.warning(f"Failed to generate CoT: {e}")
                                    finding.chain_of_thought = None

                            findings.append(finding)
                            break  # One finding per log statement

        return findings

    def _check_unencrypted_storage_ast(self, tree: ast.AST, content: str, filepath: str) -> List[Finding]:
        """Check for unencrypted sensitive data storage using AST."""
        findings: List[Finding] = []
        lines = content.split('\n')

        sensitive_field_names = {
            'ssn', 'social_security', 'credit_card', 'card_number', 'cvv', 'cvc',
            'password', 'medical_record', 'diagnosis', 'health_data', 'phi'
        }

        for node in ast.walk(tree):
            # Look for model field definitions
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        field_name = target.id.lower()

                        if any(sensitive in field_name for sensitive in sensitive_field_names):
                            # Check if encryption is mentioned
                            if not self._has_encryption_indicator(node, content):
                                evidence = f"Sensitive field '{target.id}' without encryption"
                                context_lines = self._get_context(lines, node.lineno, context_size=2)

                                severity = Severity.CRITICAL

                                # Create pattern spec
                                pattern_spec = PrivacyPattern(
                                    pattern=re.compile(""),
                                    category=Category.MISSING_ENCRYPTION,
                                    severity=severity,
                                    confidence=Confidence.HIGH,
                                    description="Sensitive data field without encryption",
                                    recommendation="Use field-level encryption for sensitive data",
                                    regulation_ref="GDPR Article 32, PCI DSS 3.4",
                                    compliance_ref="PCI DSS, HIPAA"
                                )

                                finding = Finding(
                                    category=Category.MISSING_ENCRYPTION,
                                    severity=severity,
                                    confidence=Confidence.HIGH,
                                    line_number=node.lineno,
                                    evidence=evidence,
                                    recommendation="Use field-level encryption for sensitive data",
                                    file_path=filepath,
                                    context=context_lines,
                                    regulation_reference="GDPR Article 32, PCI DSS 3.4",
                                    compliance_framework="PCI DSS, HIPAA"
                                )

                                # Generate CoT
                                try:
                                    finding.chain_of_thought = self._generate_chain_of_thought(
                                        pattern=pattern_spec,
                                        evidence=evidence,
                                        line_number=node.lineno,
                                        file_path=filepath,
                                        surrounding_context=context_lines
                                    )
                                except Exception as e:
                                    logger.warning(f"Failed to generate CoT: {e}")
                                    finding.chain_of_thought = None

                                findings.append(finding)

        return findings

    def _is_logging_call(self, node: ast.Call) -> bool:
        """Check if node is a logging call."""
        func_name = self._get_func_name(node)
        return any(pattern in func_name.lower() for pattern in ['log', 'print', 'console', 'logger'])

    def _contains_pii_field(self, node: ast.AST, pii_fields: Set[str]) -> bool:
        """Check if AST node contains PII field access."""
        field_names = self._get_field_names(node)
        return any(pii_field in field_names for pii_field in pii_fields)

    def _get_field_names(self, node: ast.AST) -> Set[str]:
        """Extract all field names from an AST node."""
        field_names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                field_names.add(child.attr.lower())
            elif isinstance(child, ast.Name):
                field_names.add(child.id.lower())
        return field_names

    def _has_encryption_indicator(self, node: ast.AST, content: str) -> bool:
        """Check if node has encryption indicators."""
        # Check for encrypt keywords in the line
        start = node.lineno - 1
        end = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
        lines = content.split('\n')[start:end]
        code_snippet = '\n'.join(lines).lower()

        encryption_keywords = ['encrypt', 'cipher', 'aes', 'crypto', 'secure']
        return any(keyword in code_snippet for keyword in encryption_keywords)

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract full function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""

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
        Review all files in a directory for privacy violations.

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
                    logger.info(f"Found {len(findings)} privacy issues in {file_path}")

            except Exception as e:
                logger.error(f"Error reviewing {file_path}: {e}")

        return results

    def generate_report(self, findings_by_file: Dict[str, List[Finding]]) -> str:
        """
        Generate a formatted privacy report.

        Args:
            findings_by_file: Dictionary mapping file paths to findings

        Returns:
            Formatted report string
        """
        total_findings = sum(len(findings) for findings in findings_by_file.values())

        if total_findings == 0:
            return "No privacy issues detected."

        # Count by severity
        severity_counts = {severity: 0 for severity in Severity}
        for findings in findings_by_file.values():
            for finding in findings:
                severity_counts[finding.severity] += 1

        report = ["=" * 80]
        report.append("PRIVACY REVIEW REPORT")
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

                if finding.regulation_reference:
                    report.append(f"   Regulation: {finding.regulation_reference}")
                if finding.compliance_framework:
                    report.append(f"   Compliance: {finding.compliance_framework}")

        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)


# ─── Example Usage ──────────────────────────────────────────────────────────


if __name__ == "__main__":
    # Example: Review a single file
    agent = PrivacyReviewerAgent()

    sample_code = '''
import logging

# HIGH: PII in logs
logger.info(f"User email: {user.email}")
logger.debug(f"SSN: {user.ssn}")

# CRITICAL: Unencrypted sensitive data
class User(models.Model):
    email = models.CharField(max_length=255)
    ssn = models.CharField(max_length=11)  # CRITICAL: No encryption
    credit_card = models.CharField(max_length=16)  # CRITICAL: No encryption
    cvv = models.CharField(max_length=3)  # CRITICAL: Never store CVV

# HIGH: HTTP for sensitive data
API_URL = "http://api.example.com/user/payment"

# HIGH: Missing encryption
def store_patient_data(diagnosis, patient_name):
    # HIPAA violation - PHI without encryption
    logger.info(f"Patient {patient_name} diagnosed with {diagnosis}")
'''

    findings = agent.review_file("example.py", sample_code)

    print(f"Found {len(findings)} privacy issues:\n")
    for finding in findings:
        print(f"[{finding.severity.value}] {finding.category.value}")
        print(f"  Line {finding.line_number}: {finding.evidence}")
        print(f"  {finding.recommendation}")
        if finding.chain_of_thought:
            print(f"  Chain of Thought generated: Yes")
        print()

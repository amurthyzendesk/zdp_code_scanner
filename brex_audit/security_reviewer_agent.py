"""
Security Reviewer Agent for Code Analysis
==========================================
A specialized agent that detects security vulnerabilities in code files, focusing on:
- Hardcoded credentials (passwords, API keys, tokens)
- SQL injection vulnerabilities
- Command injection risks
- Insecure cryptography
- Missing authentication/authorization
- Over-permissioned access (ACCOUNTADMIN, SELECT *, etc.)
- Network security issues (missing firewall rules, open ports)

Knowledge sources:
- OWASP Top 10 (SQL injection, broken auth, sensitive data exposure)
- CIS Controls (credential management, least privilege)
- Snowflake security best practices

Usage:
    from brex_audit.security_reviewer_agent import SecurityReviewerAgent

    agent = SecurityReviewerAgent()
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
    """Security finding severity levels."""
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
    """Security vulnerability categories."""
    HARDCODED_CREDENTIALS = "Hardcoded Credentials"
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    INSECURE_CRYPTO = "Insecure Cryptography"
    MISSING_AUTH = "Missing Authentication"
    MISSING_AUTHZ = "Missing Authorization"
    EXCESSIVE_PRIVILEGES = "Excessive Privileges"
    NETWORK_SECURITY = "Network Security"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    UNSAFE_FILE_OPERATIONS = "Unsafe File Operations"
    WEAK_RANDOM = "Weak Random Number Generation"


# ─── Data Classes ───────────────────────────────────────────────────────────


@dataclass
class Finding:
    """Represents a security finding from code analysis."""
    category: Category
    severity: Severity
    confidence: Confidence
    line_number: int
    evidence: str
    recommendation: str
    file_path: Optional[str] = None
    context: Optional[str] = None
    cve_reference: Optional[str] = None
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
            "cve_reference": self.cve_reference,
            "owasp_reference": self.owasp_reference,
            "cis_reference": self.cis_reference,
        }

        # Include CoT if present
        if self.chain_of_thought:
            result["chain_of_thought"] = self.chain_of_thought.to_dict()

        return result


@dataclass
class SecurityPattern:
    """Represents a security vulnerability pattern."""
    pattern: Pattern
    category: Category
    severity: Severity
    confidence: Confidence
    description: str
    recommendation: str
    owasp_ref: Optional[str] = None
    cis_ref: Optional[str] = None
    false_positive_patterns: List[Pattern] = field(default_factory=list)


# ─── Security Reviewer Agent ───────────────────────────────────────────────


class SecurityReviewerAgent:
    """
    Multi-layer security code reviewer with pattern-based and AST-based detection.

    Detection methods:
    1. Regex pattern matching for common vulnerabilities
    2. AST parsing for Python-specific security issues
    3. Context-aware analysis to reduce false positives
    4. Severity and confidence scoring
    """

    def __init__(self, enable_ast_analysis: bool = True):
        """
        Initialize the Security Reviewer Agent.

        Args:
            enable_ast_analysis: Enable AST-based analysis for Python files
        """
        self.enable_ast_analysis = enable_ast_analysis
        self.patterns = self._initialize_patterns()
        self.file_extensions = {
            '.py', '.js', '.ts', '.java', '.sql', '.sh', '.bash',
            '.yml', '.yaml', '.json', '.xml', '.env', '.config'
        }

    def _initialize_patterns(self) -> List[SecurityPattern]:
        """Initialize comprehensive security vulnerability patterns."""
        patterns = []

        # ═══ Hardcoded Credentials ═══

        # API Keys
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(api[_-]?key|apikey|api[_-]?secret|access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/]{20,})["\']',
                re.IGNORECASE
            ),
            category=Category.HARDCODED_CREDENTIALS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Hardcoded API key detected",
            recommendation="Use environment variables or secret management service (AWS Secrets Manager, HashiCorp Vault). Reference: os.environ.get('API_KEY')",
            owasp_ref="A07:2021 - Identification and Authentication Failures",
            cis_ref="CIS Control 3.4 - Protect credentials"
        ))

        # AWS Keys
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']([A-Z0-9]{20,})["\']'
            ),
            category=Category.HARDCODED_CREDENTIALS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Hardcoded AWS credentials detected",
            recommendation="Use AWS IAM roles or AWS Secrets Manager. Never commit AWS keys to code.",
            owasp_ref="A07:2021 - Identification and Authentication Failures",
            cis_ref="CIS Control 3.4 - Protect credentials"
        ))

        # Generic passwords
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']'
            ),
            category=Category.HARDCODED_CREDENTIALS,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,  # Medium due to potential false positives
            description="Hardcoded password detected",
            recommendation="Use environment variables or secret management. Example: os.environ.get('DB_PASSWORD')",
            owasp_ref="A07:2021 - Identification and Authentication Failures",
            false_positive_patterns=[
                re.compile(r'password\s*[=:]\s*["\'][\*]+["\']'),  # Masked passwords
                re.compile(r'password\s*[=:]\s*["\']example["\']'),  # Example values
                re.compile(r'password\s*[=:]\s*["\']<.*>["\']'),  # Template placeholders
            ]
        ))

        # Private keys
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
            ),
            category=Category.HARDCODED_CREDENTIALS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Private key embedded in code",
            recommendation="Store private keys in secure key management system. Use file-based keys with proper permissions (chmod 600).",
            owasp_ref="A02:2021 - Cryptographic Failures"
        ))

        # JWT tokens
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(jwt|bearer|token)\s*[=:]\s*["\']eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["\']'
            ),
            category=Category.HARDCODED_CREDENTIALS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Hardcoded JWT token detected",
            recommendation="Generate tokens dynamically. Never hardcode authentication tokens.",
            owasp_ref="A07:2021 - Identification and Authentication Failures"
        ))

        # ═══ SQL Injection ═══

        # String concatenation in SQL
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(execute|exec|cursor\.execute|db\.execute|query)\s*\([^)]*["\'].*\s*\+\s*[^"\']*["\'][^)]*\)',
                re.DOTALL
            ),
            category=Category.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="SQL query constructed with string concatenation",
            recommendation="Use parameterized queries or prepared statements. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            owasp_ref="A03:2021 - Injection",
            cis_ref="CIS Control 16.11 - Use secure programming"
        ))

        # String formatting in SQL
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(execute|exec|cursor\.execute|db\.execute|query)\s*\([^)]*["\'].*\.(format|%)[^)]*\)',
                re.DOTALL
            ),
            category=Category.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="SQL query uses string formatting (potential injection)",
            recommendation="Use parameterized queries instead of string formatting. Replace .format() or % with query parameters.",
            owasp_ref="A03:2021 - Injection"
        ))

        # F-strings in SQL
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(execute|exec|cursor\.execute|db\.execute)\s*\(\s*f["\']'
            ),
            category=Category.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="SQL query uses f-string interpolation (injection risk)",
            recommendation="Replace f-strings with parameterized queries. Use ? or %s placeholders.",
            owasp_ref="A03:2021 - Injection"
        ))

        # ═══ Snowflake-Specific Vulnerabilities ═══

        # ACCOUNTADMIN usage
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(use\s+role\s+accountadmin|role\s*[=:]\s*["\']accountadmin["\'])'
            ),
            category=Category.EXCESSIVE_PRIVILEGES,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="ACCOUNTADMIN role used (excessive privileges)",
            recommendation="Use least-privilege principle. Create custom roles with minimal required privileges. ACCOUNTADMIN should only be used for account administration.",
            cis_ref="CIS Control 5.4 - Restrict administrative privileges"
        ))

        # SELECT * usage
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)select\s+\*\s+from'
            ),
            category=Category.EXCESSIVE_PRIVILEGES,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="SELECT * used instead of specific columns",
            recommendation="Specify exact columns needed to reduce data exposure and improve performance. Example: SELECT id, name, email FROM users",
            cis_ref="CIS Control 3.3 - Configure data access control"
        ))

        # Missing WHERE clause in UPDATE/DELETE
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(update|delete)\s+\w+\s+set\s+[^;]+;(?!\s*where)',
                re.DOTALL
            ),
            category=Category.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            description="UPDATE/DELETE without WHERE clause (potential data loss)",
            recommendation="Always include WHERE clause in UPDATE/DELETE statements. Consider using transactions.",
            owasp_ref="A03:2021 - Injection"
        ))

        # ═══ Command Injection ═══

        # Shell command execution
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(os\.system|subprocess\.call|subprocess\.run|exec|eval|shell\s*=\s*True)\s*\([^)]*\+[^)]*\)',
                re.DOTALL
            ),
            category=Category.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Command execution with concatenated user input",
            recommendation="Use subprocess with list arguments instead of string concatenation. Avoid shell=True. Use shlex.quote() for necessary shell arguments.",
            owasp_ref="A03:2021 - Injection",
            cis_ref="CIS Control 16.11 - Use secure programming"
        ))

        # eval() usage
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'\beval\s*\('
            ),
            category=Category.COMMAND_INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="eval() usage detected (code injection risk)",
            recommendation="Avoid eval(). Use ast.literal_eval() for safe literal evaluation or json.loads() for JSON data.",
            owasp_ref="A03:2021 - Injection"
        ))

        # ═══ Insecure Cryptography ═══

        # MD5 usage
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(hashlib\.md5|md5\(|MD5)'
            ),
            category=Category.INSECURE_CRYPTO,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="MD5 hashing used (cryptographically broken)",
            recommendation="Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or Argon2. Example: hashlib.sha256()",
            owasp_ref="A02:2021 - Cryptographic Failures",
            cis_ref="CIS Control 3.10 - Encrypt sensitive data"
        ))

        # SHA-1 usage
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(hashlib\.sha1|sha1\(|SHA1)'
            ),
            category=Category.INSECURE_CRYPTO,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="SHA-1 hashing used (deprecated for security)",
            recommendation="Use SHA-256 or SHA-3 instead. SHA-1 is vulnerable to collision attacks.",
            owasp_ref="A02:2021 - Cryptographic Failures"
        ))

        # Weak encryption
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(DES|3DES|RC4|Blowfish)\.new\('
            ),
            category=Category.INSECURE_CRYPTO,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Weak encryption algorithm used (DES, 3DES, RC4, Blowfish)",
            recommendation="Use AES-256-GCM or ChaCha20-Poly1305 for encryption. Example: from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
            owasp_ref="A02:2021 - Cryptographic Failures"
        ))

        # ═══ Authentication/Authorization ═══

        # Missing authentication decorator
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'@app\.route\([^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\):',
                re.MULTILINE
            ),
            category=Category.MISSING_AUTH,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,  # Low confidence due to potential false positives
            description="Endpoint without authentication decorator",
            recommendation="Add authentication decorator. Example: @login_required or @requires_auth",
            owasp_ref="A07:2021 - Identification and Authentication Failures"
        ))

        # ═══ Network Security ═══

        # SSL verification disabled
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(verify\s*=\s*False|ssl[_-]?verify\s*=\s*False|CERT_NONE)'
            ),
            category=Category.NETWORK_SECURITY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="SSL certificate verification disabled",
            recommendation="Enable SSL verification. Remove verify=False from requests. Fix certificate issues instead of disabling verification.",
            owasp_ref="A02:2021 - Cryptographic Failures",
            cis_ref="CIS Control 3.10 - Encrypt sensitive data"
        ))

        # Binding to all interfaces
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(host\s*=\s*["\']0\.0\.0\.0["\']|bind\s*=\s*["\']0\.0\.0\.0)'
            ),
            category=Category.NETWORK_SECURITY,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="Server binds to all interfaces (0.0.0.0)",
            recommendation="Bind to localhost (127.0.0.1) for local services. Use specific IPs or configure firewall rules for production.",
            cis_ref="CIS Control 13.6 - Configure network access control"
        ))

        # ═══ Sensitive Data Exposure ═══

        # Debug mode in production
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(debug\s*=\s*True|DEBUG\s*=\s*True|app\.debug\s*=\s*True)'
            ),
            category=Category.SENSITIVE_DATA_EXPOSURE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Debug mode enabled (information disclosure risk)",
            recommendation="Disable debug mode in production. Set debug=False or use environment-based configuration.",
            owasp_ref="A05:2021 - Security Misconfiguration"
        ))

        # ═══ Insecure Deserialization ═══

        # Pickle usage
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'pickle\.loads?\('
            ),
            category=Category.INSECURE_DESERIALIZATION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Pickle deserialization (arbitrary code execution risk)",
            recommendation="Use JSON or other safe serialization formats. If pickle is required, validate and sign data with HMAC.",
            owasp_ref="A08:2021 - Software and Data Integrity Failures"
        ))

        # ═══ Unsafe File Operations ═══

        # Path traversal
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'(?i)(open|file)\s*\([^)]*\+[^)]*\)',
                re.DOTALL
            ),
            category=Category.UNSAFE_FILE_OPERATIONS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="File path constructed with user input (path traversal risk)",
            recommendation="Validate and sanitize file paths. Use os.path.join() and os.path.abspath(). Check if path is within allowed directory.",
            owasp_ref="A01:2021 - Broken Access Control"
        ))

        # ═══ Weak Random ═══

        # Weak random number generation
        patterns.append(SecurityPattern(
            pattern=re.compile(
                r'\brandom\.(random|randint|choice)\('
            ),
            category=Category.WEAK_RANDOM,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="Non-cryptographic random number generation",
            recommendation="Use secrets module for security-sensitive operations. Example: secrets.token_bytes(32) or secrets.SystemRandom()",
            owasp_ref="A02:2021 - Cryptographic Failures"
        ))

        return patterns

    def _generate_chain_of_thought(
        self,
        pattern: SecurityPattern,
        evidence: str,
        line_number: int,
        file_path: str,
        surrounding_context: str
    ) -> ChainOfThought:
        """
        Generate Chain of Thought reasoning for a finding.

        Args:
            pattern: The security pattern that matched
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
        if pattern.category == Category.SQL_INJECTION:
            return self._generate_sql_injection_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.HARDCODED_CREDENTIALS:
            return self._generate_credentials_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.COMMAND_INJECTION:
            return self._generate_command_injection_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.INSECURE_CRYPTO:
            return self._generate_insecure_crypto_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.NETWORK_SECURITY:
            return self._generate_network_security_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.EXCESSIVE_PRIVILEGES:
            return self._generate_excessive_privileges_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.INSECURE_DESERIALIZATION:
            return self._generate_deserialization_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.UNSAFE_FILE_OPERATIONS:
            return self._generate_file_operations_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.SENSITIVE_DATA_EXPOSURE:
            return self._generate_data_exposure_cot(pattern, evidence, line_number, file_path, surrounding_context)
        elif pattern.category == Category.MISSING_AUTH:
            return self._generate_missing_auth_cot(pattern, evidence, line_number, file_path, surrounding_context)
        else:
            # Generic CoT for other categories
            return self._generate_generic_cot(pattern, evidence, line_number, file_path, surrounding_context)

    def _generate_sql_injection_cot(self, pattern: SecurityPattern, evidence: str,
                                   line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for SQL injection findings."""
        # Determine specific signals based on evidence
        signals = []
        if "+" in evidence or "concat" in evidence.lower():
            signals.append("String concatenation")
        if "format" in evidence or "%" in evidence:
            signals.append("String formatting")
        if "f'" in evidence or 'f"' in evidence:
            signals.append("F-string interpolation")
        if "execute" in evidence.lower():
            signals.append("SQL execute call")
        if not any(x in evidence for x in ["?", "%s", "paramstyle"]):
            signals.append("No parameterization")

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="SQL injection via string concatenation/formatting",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Regex pattern matching + String operation detection",
                signals_observed=signals,
                agent_name="SecurityReviewerAgent",
                check_name="_check_sql_injection"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Direct SQL injection allows unauthorized database access and manipulation",
                impact_description="Attacker can read, modify, or delete database records; bypass authentication; extract sensitive data; potential full database compromise",
                affected_assets=["Database", "User data", "Authentication system", "Application integrity"],
                attack_surface="Any endpoint that accepts user input and constructs SQL queries",
                data_sensitivity="PII + Financial + Authentication credentials",
                compliance_impact=["GDPR Article 32", "PCI DSS 6.5.1", "SOC 2 CC6.1", "HIPAA 164.312"]
            ),
            attack=AttackScenario(
                attack_vector="HTTP request with SQL payload in input parameter",
                attack_steps=[
                    "Identify vulnerable input parameter",
                    "Inject SQL payload (e.g., ' OR '1'='1' -- )",
                    "Bypass authentication or extract data",
                    "Execute arbitrary SQL commands"
                ],
                required_access="API/web access with ability to send input (authenticated or unauthenticated)",
                exploitability_rating="Easy",
                similar_cves=["CVE-2019-16278", "CVE-2020-24949", "CVE-2021-41277"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Clear string concatenation/formatting pattern", "SQL execution method detected", "No parameterization visible"],
                strong_evidence=["String operation with SQL execute", "User input variable in query"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use parameterized queries (prepared statements)",
                fix_rationale="Parameterization separates SQL logic from data, preventing injection by treating user input as data only, never as SQL code",
                alternative_fixes=[
                    "Use ORM (SQLAlchemy, Django ORM) with proper query methods",
                    "Escape user input with database-specific functions (less safe, not recommended)",
                    "Implement strict input validation (defense in depth, not primary fix)"
                ],
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Test with SQL injection payloads: ' OR '1'='1, '; DROP TABLE users--, UNION SELECT attacks"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_credentials_cot(self, pattern: SecurityPattern, evidence: str,
                                  line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for hardcoded credentials findings."""
        # Determine credential type
        cred_type = "API key" if "api" in evidence.lower() else \
                    "AWS credentials" if "aws" in evidence.lower() else \
                    "JWT token" if "jwt" in evidence.lower() or "bearer" in evidence.lower() else \
                    "Private key" if "PRIVATE KEY" in evidence else \
                    "Password"

        signals = [f"Hardcoded {cred_type} in source code", "String literal assignment", "No environment variable usage"]

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=f"Hardcoded {cred_type} in source code",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for credential patterns and string literals",
                signals_observed=signals,
                agent_name="SecurityReviewerAgent",
                check_name="_check_hardcoded_credentials"
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"Hardcoded credentials in source code can be extracted by anyone with code access, leaked via version control, or exposed in builds",
                impact_description=f"Attacker gains unauthorized access using the exposed {cred_type}; potential account takeover, data breach, or service compromise",
                affected_assets=["Authentication system", "User accounts", "API access", "Service credentials"],
                attack_surface="Source code repositories, build artifacts, decompiled binaries, logs",
                data_sensitivity="Critical - Authentication credentials",
                compliance_impact=["NIST SP 800-53 IA-5", "CIS Control 3.4", "PCI DSS 8.2.1", "GDPR Article 32"]
            ),
            attack=AttackScenario(
                attack_vector="Access to source code via repository, build artifacts, or decompilation",
                attack_steps=[
                    "Obtain source code (git clone, leaked repo, insider access)",
                    "Search for credential patterns in code",
                    "Extract hardcoded credentials",
                    "Use credentials to access systems/APIs"
                ],
                required_access="Read access to code repository or build artifacts",
                exploitability_rating="Easy",
                similar_cves=["CVE-2021-39175", "CVE-2022-24784", "CVE-2023-22620"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=[f"Clear {cred_type} pattern", "String literal value", "No environment variable"],
                strong_evidence=["Hardcoded string value", "Credential pattern match"],
                weak_evidence=["Could be example/placeholder"] if confidence_level != ConfidenceLevel.HIGH else [],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use environment variables or secret management service",
                fix_rationale="Environment variables keep secrets out of source code; secret management services (AWS Secrets Manager, HashiCorp Vault) provide encryption, rotation, and audit logging",
                alternative_fixes=[
                    "Use secret management service (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)",
                    "Use encrypted config files with access controls",
                    "For local dev: use .env files (with .gitignore) + python-dotenv"
                ],
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Verify secrets are loaded from environment, not hardcoded; test secret rotation"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_command_injection_cot(self, pattern: SecurityPattern, evidence: str,
                                       line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for command injection findings."""
        # Determine dangerous function
        func_name = "eval()" if "eval" in evidence else \
                    "os.system()" if "os.system" in evidence else \
                    "subprocess with shell=True" if "shell" in evidence.lower() else \
                    "exec()" if "exec" in evidence else \
                    "subprocess"

        signals = [f"{func_name} call detected", "String concatenation with user input"]
        if "shell" in evidence.lower() and "true" in evidence.lower():
            signals.append("shell=True parameter")

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=f"Command injection via {func_name}",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for dangerous function calls with string operations",
                signals_observed=signals,
                agent_name="SecurityReviewerAgent",
                check_name="_check_command_injection"
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"{func_name} with user input allows arbitrary command execution on the server",
                impact_description="Attacker can execute arbitrary operating system commands; potential full system compromise, data theft, ransomware deployment, lateral movement",
                affected_assets=["Operating system", "File system", "Running processes", "Network access", "Other systems"],
                attack_surface="Any endpoint that accepts user input passed to system commands",
                data_sensitivity="Critical - Full system access",
                compliance_impact=["CIS Control 16.11", "NIST SP 800-53 SI-10", "OWASP A03:2021"]
            ),
            attack=AttackScenario(
                attack_vector="HTTP request with shell command characters in input parameter",
                attack_steps=[
                    "Identify input parameter passed to system command",
                    "Inject shell metacharacters (; && || | ` $())",
                    "Append malicious commands",
                    "Execute arbitrary commands on server"
                ],
                required_access="API/web access with ability to send input",
                exploitability_rating="Easy",
                similar_cves=["CVE-2021-44228 (Log4Shell)", "CVE-2022-22965 (Spring4Shell)", "CVE-2023-38545"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=[f"{func_name} usage", "String concatenation/formatting", "User input in command"],
                strong_evidence=[f"Dangerous function {func_name}", "String operation with command"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use subprocess with list arguments and avoid shell=True",
                fix_rationale="List arguments prevent shell interpretation of metacharacters; avoiding shell=True removes shell command injection vector entirely",
                alternative_fixes=[
                    "If eval() is used, replace with ast.literal_eval() or json.loads()",
                    "Use shlex.quote() for necessary shell arguments (defense in depth)",
                    "Implement strict input validation with allowlist",
                    "Use library functions instead of shell commands where possible"
                ],
                implementation_complexity="Medium",
                breaking_changes=False,
                testing_guidance="Test with command injection payloads: ; ls, && whoami, | cat /etc/passwd"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_insecure_crypto_cot(self, pattern: SecurityPattern, evidence: str,
                                      line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for insecure cryptography findings."""
        # Determine weak algorithm
        algo = "MD5" if "md5" in evidence.lower() else \
               "SHA-1" if "sha1" in evidence.lower() else \
               "DES/3DES/RC4/Blowfish" if any(x in evidence for x in ["DES", "3DES", "RC4", "Blowfish"]) else \
               "Weak cryptography"

        severity = pattern.severity

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched=f"Use of weak/broken cryptographic algorithm: {algo}",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for deprecated cryptographic functions",
                signals_observed=[f"{algo} algorithm usage", "Cryptographically broken algorithm"],
                agent_name="SecurityReviewerAgent",
                check_name="_check_insecure_crypto"
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"{algo} is cryptographically broken and vulnerable to collision/preimage attacks",
                impact_description="Attacker can forge signatures, crack password hashes, decrypt data, or create collisions; undermines security guarantees",
                affected_assets=["Cryptographic keys", "Password hashes", "Digital signatures", "Encrypted data"],
                attack_surface="Any data protected by weak cryptography",
                data_sensitivity="High - Cryptographically protected data",
                compliance_impact=["NIST SP 800-131A", "PCI DSS 4.1", "FIPS 140-2", "GDPR Article 32"]
            ),
            attack=AttackScenario(
                attack_vector="Cryptanalytic attacks on weak algorithm",
                attack_steps=[
                    "Obtain hash/ciphertext",
                    f"Use known {algo} weaknesses (collision, rainbow tables, etc.)",
                    "Crack password or forge signature",
                    "Gain unauthorized access"
                ],
                required_access="Access to hash values or encrypted data",
                exploitability_rating="Medium" if algo == "SHA-1" else "Easy",
                similar_cves=["CVE-2020-10735 (MD5)", "CVE-2017-15361 (SHA-1 collision)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=[f"Direct {algo} algorithm usage", "Industry-known weakness"],
                strong_evidence=[f"{algo} function call", "No use of modern alternatives"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use SHA-256, SHA-3, or Argon2/bcrypt for passwords",
                fix_rationale="Modern algorithms provide necessary security guarantees; SHA-256/SHA-3 for hashing, Argon2/bcrypt/scrypt for password hashing (includes salt and work factor)",
                alternative_fixes=[
                    "For general hashing: hashlib.sha256() or hashlib.sha3_256()",
                    "For password hashing: bcrypt, scrypt, or Argon2 (preferred)",
                    "For encryption: AES-256-GCM or ChaCha20-Poly1305"
                ],
                implementation_complexity="Easy",
                breaking_changes=True,
                testing_guidance="Re-hash existing data; plan migration strategy for passwords"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_network_security_cot(self, pattern: SecurityPattern, evidence: str,
                                       line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for network security findings."""
        issue_type = "SSL verification disabled" if "verify" in evidence.lower() or "cert_none" in evidence.lower() else \
                     "Binding to all interfaces (0.0.0.0)"

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        if "verify" in issue_type.lower():
            return ChainOfThought(
                detection=DetectionReasoning(
                    pattern_matched="SSL/TLS certificate verification disabled",
                    evidence_summary=f"Line {line_number}: {evidence[:100]}",
                    detection_method="Pattern matching for verify=False or CERT_NONE",
                    signals_observed=["SSL verification disabled", "verify=False parameter"],
                    agent_name="SecurityReviewerAgent",
                    check_name="_check_network_security"
                ),
                risk=RiskAnalysis(
                    severity_reasoning="Disabling SSL verification allows man-in-the-middle attacks",
                    impact_description="Attacker can intercept, read, and modify encrypted traffic; steal credentials, session tokens, or sensitive data",
                    affected_assets=["Network communications", "API credentials", "User data in transit"],
                    attack_surface="Any network communication using disabled verification",
                    data_sensitivity="High - Data in transit",
                    compliance_impact=["PCI DSS 4.1", "NIST SP 800-52", "GDPR Article 32"]
                ),
                attack=AttackScenario(
                    attack_vector="Man-in-the-middle attack on network communication",
                    attack_steps=[
                        "Position attacker between client and server",
                        "Intercept SSL/TLS connection",
                        "Present invalid/self-signed certificate",
                        "Client accepts due to disabled verification",
                        "Decrypt and read/modify traffic"
                    ],
                    required_access="Network access (same network or ISP level)",
                    exploitability_rating="Medium",
                    similar_cves=["CVE-2014-0092", "CVE-2015-5237"]
                ),
                confidence=ConfidenceRationale(
                    confidence_level=confidence_level,
                    primary_factors=["Explicit verify=False", "Clear security control bypass"],
                    strong_evidence=["verify=False in code", "SSL_CERT_NONE constant"],
                    weak_evidence=[],
                    agent_agreement=1
                ),
                remediation=RemediationReasoning(
                    recommended_fix="Enable SSL verification (remove verify=False)",
                    fix_rationale="SSL verification ensures communication with legitimate server; validates certificate chain and hostname",
                    alternative_fixes=[
                        "If certificate issues exist, fix certificate configuration",
                        "For self-signed certs in testing, use proper CA bundle",
                        "Never disable in production"
                    ],
                    implementation_complexity="Easy",
                    breaking_changes=False,
                    testing_guidance="Verify SSL connections work with valid certificates"
                ),
                generated_by_agent="SecurityReviewerAgent",
                generated_at=datetime.now().isoformat()
            )
        else:
            return ChainOfThought(
                detection=DetectionReasoning(
                    pattern_matched="Server binding to all network interfaces (0.0.0.0)",
                    evidence_summary=f"Line {line_number}: {evidence[:100]}",
                    detection_method="Pattern matching for 0.0.0.0 bind address",
                    signals_observed=["Bind to 0.0.0.0", "All interfaces exposed"],
                    agent_name="SecurityReviewerAgent",
                    check_name="_check_network_security"
                ),
                risk=RiskAnalysis(
                    severity_reasoning="Binding to 0.0.0.0 exposes service to all network interfaces including public networks",
                    impact_description="Service accessible from external networks; increases attack surface; potential unauthorized access if firewall misconfigured",
                    affected_assets=["Application service", "Internal APIs", "Admin interfaces"],
                    attack_surface="All network interfaces including public internet",
                    data_sensitivity="Medium - Service exposure",
                    compliance_impact=["CIS Control 13.6", "NIST SP 800-53 SC-7"]
                ),
                attack=AttackScenario(
                    attack_vector="Direct network access to exposed service",
                    attack_steps=[
                        "Scan for open ports on public interface",
                        "Identify exposed service",
                        "Attempt to exploit service vulnerabilities",
                        "Gain unauthorized access"
                    ],
                    required_access="Network access to server",
                    exploitability_rating="Easy",
                    similar_cves=["CVE-2021-3129", "CVE-2022-0847"]
                ),
                confidence=ConfidenceRationale(
                    confidence_level=confidence_level,
                    primary_factors=["Explicit 0.0.0.0 bind", "All interfaces exposed"],
                    strong_evidence=["host='0.0.0.0' or bind='0.0.0.0'"],
                    weak_evidence=["May have firewall protection"],
                    agent_agreement=1
                ),
                remediation=RemediationReasoning(
                    recommended_fix="Bind to localhost (127.0.0.1) for local services",
                    fix_rationale="Binding to localhost restricts access to local machine only; use specific IPs for multi-interface servers",
                    alternative_fixes=[
                        "Bind to specific internal IP",
                        "Configure firewall rules (defense in depth)",
                        "Use reverse proxy for public access"
                    ],
                    implementation_complexity="Easy",
                    breaking_changes=False,
                    testing_guidance="Verify service accessibility from intended networks only"
                ),
                generated_by_agent="SecurityReviewerAgent",
                generated_at=datetime.now().isoformat()
            )

    def _generate_excessive_privileges_cot(self, pattern: SecurityPattern, evidence: str,
                                          line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for excessive privileges findings."""
        priv_type = "ACCOUNTADMIN role" if "accountadmin" in evidence.lower() else \
                    "SELECT * query"

        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        if "accountadmin" in priv_type.lower():
            severity = Severity.HIGH
            return ChainOfThought(
                detection=DetectionReasoning(
                    pattern_matched="Use of ACCOUNTADMIN role (excessive privileges)",
                    evidence_summary=f"Line {line_number}: {evidence[:100]}",
                    detection_method="Pattern matching for ACCOUNTADMIN usage",
                    signals_observed=["ACCOUNTADMIN role usage", "Excessive privileges", "Violation of least privilege"],
                    agent_name="SecurityReviewerAgent",
                    check_name="_check_excessive_privileges"
                ),
                risk=RiskAnalysis(
                    severity_reasoning="ACCOUNTADMIN has unrestricted access to all Snowflake objects and operations",
                    impact_description="Compromised credentials allow full account takeover; ability to access, modify, or delete all data; create backdoors; disable auditing",
                    affected_assets=["Entire Snowflake account", "All databases", "All warehouses", "All users", "Audit logs"],
                    attack_surface="Any code execution context with ACCOUNTADMIN credentials",
                    data_sensitivity="Critical - Full account access",
                    compliance_impact=["CIS Control 5.4", "SOC 2 CC6.1", "NIST SP 800-53 AC-6"]
                ),
                attack=AttackScenario(
                    attack_vector="Credential theft or code execution in ACCOUNTADMIN context",
                    attack_steps=[
                        "Obtain ACCOUNTADMIN credentials from code/logs",
                        "Connect to Snowflake with ACCOUNTADMIN",
                        "Access all data, create backdoor users",
                        "Exfiltrate data or establish persistence"
                    ],
                    required_access="Access to credentials or code execution",
                    exploitability_rating="Easy",
                    similar_cves=[]
                ),
                confidence=ConfidenceRationale(
                    confidence_level=confidence_level,
                    primary_factors=["Explicit ACCOUNTADMIN usage", "Clear privilege violation"],
                    strong_evidence=["ACCOUNTADMIN role in code"],
                    weak_evidence=[],
                    agent_agreement=1
                ),
                remediation=RemediationReasoning(
                    recommended_fix="Use custom role with minimum required privileges",
                    fix_rationale="Least privilege principle limits blast radius of credential compromise; custom roles grant only necessary permissions",
                    alternative_fixes=[
                        "Create task-specific roles (e.g., READ_ONLY_ANALYST)",
                        "Use SYSADMIN for most admin tasks",
                        "Reserve ACCOUNTADMIN for account-level operations only"
                    ],
                    implementation_complexity="Medium",
                    breaking_changes=True,
                    testing_guidance="Test with custom role to ensure required operations work"
                ),
                generated_by_agent="SecurityReviewerAgent",
                generated_at=datetime.now().isoformat()
            )
        else:
            # SELECT *
            return ChainOfThought(
                detection=DetectionReasoning(
                    pattern_matched="SELECT * query (excessive data exposure)",
                    evidence_summary=f"Line {line_number}: {evidence[:100]}",
                    detection_method="Pattern matching for SELECT * queries",
                    signals_observed=["SELECT * usage", "Over-fetching data", "No column specification"],
                    agent_name="SecurityReviewerAgent",
                    check_name="_check_excessive_privileges"
                ),
                risk=RiskAnalysis(
                    severity_reasoning="SELECT * retrieves all columns including potentially sensitive ones not needed by application",
                    impact_description="Increases data exposure risk; may retrieve PII, credentials, or sensitive fields; performance impact; harder to audit data access",
                    affected_assets=["Database records", "PII", "Sensitive columns"],
                    attack_surface="Application data access layer",
                    data_sensitivity="Medium - Excessive data exposure",
                    compliance_impact=["GDPR Article 5 (data minimization)", "PCI DSS 3.2", "SOC 2 CC6.1"]
                ),
                attack=AttackScenario(
                    attack_vector="SQL injection or application compromise",
                    attack_steps=[
                        "Exploit SQL injection or application vulnerability",
                        "Execute SELECT * query",
                        "Retrieve all columns including sensitive fields",
                        "Extract more data than application needs"
                    ],
                    required_access="Application access or SQL injection",
                    exploitability_rating="Medium",
                    similar_cves=[]
                ),
                confidence=ConfidenceRationale(
                    confidence_level=confidence_level,
                    primary_factors=["SELECT * pattern", "Data minimization violation"],
                    strong_evidence=["SELECT * in query"],
                    weak_evidence=["May be acceptable in some contexts"],
                    agent_agreement=1
                ),
                remediation=RemediationReasoning(
                    recommended_fix="Specify exact columns needed",
                    fix_rationale="Column specification implements data minimization; reduces exposure; improves performance and maintainability",
                    alternative_fixes=[
                        "Use views with specific columns",
                        "Use ORM select_related/only methods"
                    ],
                    implementation_complexity="Easy",
                    breaking_changes=False,
                    testing_guidance="Verify application still receives required data"
                ),
                generated_by_agent="SecurityReviewerAgent",
                generated_at=datetime.now().isoformat()
            )

    def _generate_deserialization_cot(self, pattern: SecurityPattern, evidence: str,
                                      line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for insecure deserialization findings."""
        confidence_level = ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.HIGH

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Insecure deserialization using pickle",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for pickle.loads/pickle.load",
                signals_observed=["pickle.loads() or pickle.load()", "Arbitrary code execution risk"],
                agent_name="SecurityReviewerAgent",
                check_name="_check_insecure_deserialization"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Pickle deserialization can execute arbitrary Python code embedded in malicious data",
                impact_description="Attacker can achieve arbitrary code execution; full system compromise; data theft; ransomware; lateral movement",
                affected_assets=["Application server", "File system", "Databases", "Network"],
                attack_surface="Any endpoint that deserializes pickle data",
                data_sensitivity="Critical - Code execution",
                compliance_impact=["OWASP A08:2021", "CIS Control 16.11"]
            ),
            attack=AttackScenario(
                attack_vector="Malicious pickle payload sent to application",
                attack_steps=[
                    "Craft malicious pickle payload with __reduce__ method",
                    "Send payload to application endpoint",
                    "Application deserializes pickle",
                    "Arbitrary code executes on server"
                ],
                required_access="Ability to send data to application",
                exploitability_rating="Medium",
                similar_cves=["CVE-2019-16729", "CVE-2021-3177"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["pickle.loads/load usage", "Known RCE vulnerability"],
                strong_evidence=["pickle deserialization call"],
                weak_evidence=["May be used safely in trusted contexts"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Use JSON or MessagePack for serialization",
                fix_rationale="JSON and MessagePack are data-only formats without code execution; safer for untrusted data",
                alternative_fixes=[
                    "If pickle required, sign/MAC data and validate signature",
                    "Use restricted unpickler with allowlist",
                    "Validate and sanitize before deserialization"
                ],
                implementation_complexity="Medium",
                breaking_changes=True,
                testing_guidance="Test data serialization/deserialization with new format"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_file_operations_cot(self, pattern: SecurityPattern, evidence: str,
                                      line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for unsafe file operations findings."""
        confidence_level = ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.HIGH

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="File path constructed with user input (path traversal risk)",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for file operations with concatenation",
                signals_observed=["File operation with user input", "String concatenation", "Path traversal risk"],
                agent_name="SecurityReviewerAgent",
                check_name="_check_file_operations"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Path traversal allows reading/writing arbitrary files outside intended directory",
                impact_description="Attacker can read sensitive files (/etc/passwd, config files, source code); write malicious files; overwrite critical files",
                affected_assets=["File system", "Application files", "System files", "Configuration"],
                attack_surface="File upload, download, or access endpoints",
                data_sensitivity="High - File system access",
                compliance_impact=["OWASP A01:2021", "CIS Control 3.3"]
            ),
            attack=AttackScenario(
                attack_vector="File path parameter with ../ sequences",
                attack_steps=[
                    "Identify file operation with user input",
                    "Inject ../ sequences to traverse directories",
                    "Access files outside intended directory",
                    "Read sensitive files or upload malicious files"
                ],
                required_access="Access to file operation endpoint",
                exploitability_rating="Easy",
                similar_cves=["CVE-2021-41773", "CVE-2022-24990"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["File operation with concatenation", "User input in path"],
                strong_evidence=["String concatenation with file operation"],
                weak_evidence=["May have validation elsewhere"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Validate and sanitize file paths; use os.path.abspath() and check containment",
                fix_rationale="Path validation ensures file access stays within allowed directory; abspath() resolves ../ sequences",
                alternative_fixes=[
                    "Use allowlist of permitted files",
                    "Use UUID/hash for filenames instead of user input",
                    "Implement chroot or sandboxing"
                ],
                implementation_complexity="Medium",
                breaking_changes=False,
                testing_guidance="Test with path traversal payloads: ../, ../../, etc."
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_data_exposure_cot(self, pattern: SecurityPattern, evidence: str,
                                    line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for sensitive data exposure findings."""
        confidence_level = ConfidenceLevel.HIGH if pattern.confidence == Confidence.HIGH else (
            ConfidenceLevel.MEDIUM if pattern.confidence == Confidence.MEDIUM else ConfidenceLevel.LOW
        )

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Debug mode enabled (information disclosure risk)",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for debug=True configuration",
                signals_observed=["debug=True", "DEBUG=True", "Verbose error reporting"],
                agent_name="SecurityReviewerAgent",
                check_name="_check_sensitive_data_exposure"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Debug mode exposes stack traces, variable values, and internal application details",
                impact_description="Attacker gains insights into application internals; discovers vulnerabilities; obtains sensitive data from error messages",
                affected_assets=["Application internals", "Source code paths", "Variable values", "Stack traces"],
                attack_surface="Error pages and debug output",
                data_sensitivity="Medium - Information disclosure",
                compliance_impact=["OWASP A05:2021", "CIS Control 16.11"]
            ),
            attack=AttackScenario(
                attack_vector="Trigger application errors to view debug output",
                attack_steps=[
                    "Send malformed requests to trigger errors",
                    "View detailed error messages and stack traces",
                    "Extract file paths, database schemas, credentials",
                    "Use information for further attacks"
                ],
                required_access="Application access",
                exploitability_rating="Easy",
                similar_cves=["CVE-2021-44228 (Log4Shell debug exposure)"]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["Explicit debug=True", "Security misconfiguration"],
                strong_evidence=["debug=True in code"],
                weak_evidence=[],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Disable debug mode in production (debug=False)",
                fix_rationale="Production applications should use generic error pages; log detailed errors server-side only",
                alternative_fixes=[
                    "Use environment-based configuration",
                    "Implement proper error logging",
                    "Show user-friendly error pages"
                ],
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Verify error handling shows generic messages to users"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_missing_auth_cot(self, pattern: SecurityPattern, evidence: str,
                                   line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
        """Generate CoT for missing authentication findings."""
        confidence_level = ConfidenceLevel.LOW  # Always LOW due to high false positive rate

        return ChainOfThought(
            detection=DetectionReasoning(
                pattern_matched="Endpoint without authentication decorator",
                evidence_summary=f"Line {line_number}: {evidence[:100]}",
                detection_method="Pattern matching for route decorators without auth",
                signals_observed=["@app.route without @login_required", "No authentication decorator visible"],
                agent_name="SecurityReviewerAgent",
                check_name="_check_missing_auth"
            ),
            risk=RiskAnalysis(
                severity_reasoning="Unauthenticated endpoints may allow unauthorized access to functionality or data",
                impact_description="Potential unauthorized access; data exposure; unauthorized operations",
                affected_assets=["Endpoint functionality", "Data accessed by endpoint"],
                attack_surface="Unauthenticated endpoint",
                data_sensitivity="Unknown - Depends on endpoint purpose",
                compliance_impact=["OWASP A07:2021"]
            ),
            attack=AttackScenario(
                attack_vector="Direct access to unauthenticated endpoint",
                attack_steps=[
                    "Discover endpoint URL",
                    "Access without authentication",
                    "Exploit exposed functionality"
                ],
                required_access="Network access to application",
                exploitability_rating="Easy",
                similar_cves=[]
            ),
            confidence=ConfidenceRationale(
                confidence_level=confidence_level,
                primary_factors=["No auth decorator visible", "May be public endpoint"],
                strong_evidence=[],
                weak_evidence=["Auth may be implemented elsewhere", "May be intentionally public", "Framework may provide default auth"],
                agent_agreement=1
            ),
            remediation=RemediationReasoning(
                recommended_fix="Add authentication decorator if endpoint requires auth",
                fix_rationale="Authentication decorators enforce access control at the endpoint level",
                alternative_fixes=[
                    "Verify if endpoint should be public",
                    "Use middleware authentication",
                    "Implement OAuth/JWT authentication"
                ],
                implementation_complexity="Easy",
                breaking_changes=False,
                testing_guidance="Verify authentication is required for sensitive endpoints"
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def _generate_generic_cot(self, pattern: SecurityPattern, evidence: str,
                             line_number: int, file_path: str, surrounding_context: str) -> ChainOfThought:
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
                agent_name="SecurityReviewerAgent",
                check_name="generic_pattern_check"
            ),
            risk=RiskAnalysis(
                severity_reasoning=f"{pattern.severity.value} severity: {pattern.description}",
                impact_description="Security vulnerability detected; potential risk to application security",
                affected_assets=["Application"],
                attack_surface="Code location identified",
                data_sensitivity="Unknown"
            ),
            attack=AttackScenario(
                attack_vector="Exploit detected vulnerability",
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
                fix_rationale="Apply recommended security fix",
                implementation_complexity="Medium",
                breaking_changes=False
            ),
            generated_by_agent="SecurityReviewerAgent",
            generated_at=datetime.now().isoformat()
        )

    def review_file(self, filepath: str, content: str) -> List[Finding]:
        """
        Review a file for security vulnerabilities.

        Args:
            filepath: Path to the file being reviewed
            content: File content as string

        Returns:
            List of Finding objects representing detected vulnerabilities
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
        """Detect vulnerabilities using regex patterns."""
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

    def _ast_based_detection(self, filepath: str, content: str) -> List[Finding]:
        """Detect Python-specific vulnerabilities using AST parsing."""
        findings: List[Finding] = []

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            logger.debug(f"Syntax error in {filepath}, skipping AST analysis: {e}")
            return findings

        # Check for hardcoded secrets in assignments
        findings.extend(self._check_hardcoded_assignments(tree, content, filepath))

        # Check for SQL injection in database calls
        findings.extend(self._check_sql_injection_ast(tree, content, filepath))

        # Check for command injection
        findings.extend(self._check_command_injection_ast(tree, content, filepath))

        # Check for insecure functions
        findings.extend(self._check_insecure_functions(tree, content, filepath))

        return findings

    def _check_hardcoded_assignments(self, tree: ast.AST, content: str, filepath: str) -> List[Finding]:
        """Check for hardcoded secrets in variable assignments."""
        findings: List[Finding] = []
        lines = content.split('\n')

        secret_var_names = {
            'password', 'passwd', 'pwd', 'api_key', 'apikey', 'secret',
            'token', 'auth_token', 'access_token', 'private_key'
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()

                        # Check if variable name suggests a secret
                        if any(secret in var_name for secret in secret_var_names):
                            # Check if value is a non-empty string constant
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                value = node.value.value

                                # Skip obvious placeholders
                                if value and not self._is_placeholder(value):
                                    evidence = f"{target.id} = '{value[:50]}...'"
                                    context_lines = self._get_context(lines, node.lineno, context_size=2)

                                    # Create pattern spec for CoT generation
                                    pattern_spec = SecurityPattern(
                                        pattern=re.compile(""),  # Dummy pattern
                                        category=Category.HARDCODED_CREDENTIALS,
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.MEDIUM,
                                        description="Hardcoded credentials in variable assignment",
                                        recommendation="Use environment variables or secret management. Example: os.environ.get('SECRET_NAME')",
                                        owasp_ref="A07:2021 - Identification and Authentication Failures"
                                    )

                                    finding = Finding(
                                        category=Category.HARDCODED_CREDENTIALS,
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.MEDIUM,
                                        line_number=node.lineno,
                                        evidence=evidence,
                                        recommendation="Use environment variables or secret management. Example: os.environ.get('SECRET_NAME')",
                                        file_path=filepath,
                                        context=context_lines,
                                        owasp_reference="A07:2021 - Identification and Authentication Failures"
                                    )

                                    # Generate CoT for CRITICAL finding
                                    try:
                                        finding.chain_of_thought = self._generate_chain_of_thought(
                                            pattern=pattern_spec,
                                            evidence=evidence,
                                            line_number=node.lineno,
                                            file_path=filepath,
                                            surrounding_context=context_lines
                                        )
                                    except Exception as e:
                                        logger.warning(f"Failed to generate CoT for finding at line {node.lineno}: {e}")
                                        finding.chain_of_thought = None

                                    findings.append(finding)

        return findings

    def _check_sql_injection_ast(self, tree: ast.AST, content: str, filepath: str) -> List[Finding]:
        """Check for SQL injection vulnerabilities using AST."""
        findings: List[Finding] = []
        lines = content.split('\n')

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if it's a database execute call
                if self._is_db_execute_call(node):
                    # Check if SQL is constructed with string operations
                    if len(node.args) > 0:
                        sql_arg = node.args[0]
                        evidence = None
                        description = None

                        # Check for f-strings
                        if isinstance(sql_arg, ast.JoinedStr):
                            evidence = "SQL query uses f-string interpolation"
                            description = "SQL injection via f-string interpolation"
                        # Check for string concatenation
                        elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
                            evidence = "SQL query uses string concatenation"
                            description = "SQL injection via string concatenation"

                        if evidence:
                            context_lines = self._get_context(lines, node.lineno, context_size=2)

                            # Create pattern spec for CoT generation
                            pattern_spec = SecurityPattern(
                                pattern=re.compile(""),  # Dummy pattern
                                category=Category.SQL_INJECTION,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                description=description,
                                recommendation="Use parameterized queries with placeholders instead of string operations",
                                owasp_ref="A03:2021 - Injection"
                            )

                            finding = Finding(
                                category=Category.SQL_INJECTION,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                line_number=node.lineno,
                                evidence=evidence,
                                recommendation="Use parameterized queries with placeholders instead of string operations",
                                file_path=filepath,
                                context=context_lines,
                                owasp_reference="A03:2021 - Injection"
                            )

                            # Generate CoT for CRITICAL finding
                            try:
                                finding.chain_of_thought = self._generate_chain_of_thought(
                                    pattern=pattern_spec,
                                    evidence=evidence,
                                    line_number=node.lineno,
                                    file_path=filepath,
                                    surrounding_context=context_lines
                                )
                            except Exception as e:
                                logger.warning(f"Failed to generate CoT for finding at line {node.lineno}: {e}")
                                finding.chain_of_thought = None

                            findings.append(finding)

        return findings

    def _check_command_injection_ast(self, tree: ast.AST, content: str, filepath: str) -> List[Finding]:
        """Check for command injection vulnerabilities."""
        findings: List[Finding] = []
        lines = content.split('\n')

        dangerous_funcs = {'os.system', 'subprocess.call', 'subprocess.run', 'exec', 'eval'}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                if func_name in dangerous_funcs:
                    # Check for shell=True
                    has_shell_true = any(
                        isinstance(kw, ast.keyword) and
                        kw.arg == 'shell' and
                        isinstance(kw.value, ast.Constant) and
                        kw.value.value is True
                        for kw in node.keywords
                    )

                    if has_shell_true or func_name in {'os.system', 'exec', 'eval'}:
                        severity = Severity.CRITICAL if func_name == 'eval' else Severity.HIGH
                        evidence = f"Dangerous function call: {func_name}"
                        if has_shell_true:
                            evidence += " with shell=True"

                        context_lines = self._get_context(lines, node.lineno, context_size=2)

                        # Create pattern spec for CoT generation
                        pattern_spec = SecurityPattern(
                            pattern=re.compile(""),  # Dummy pattern
                            category=Category.COMMAND_INJECTION,
                            severity=severity,
                            confidence=Confidence.HIGH,
                            description=f"Command injection via {func_name}",
                            recommendation="Avoid shell=True. Use list arguments for subprocess. Avoid eval() entirely.",
                            owasp_ref="A03:2021 - Injection"
                        )

                        finding = Finding(
                            category=Category.COMMAND_INJECTION,
                            severity=severity,
                            confidence=Confidence.HIGH,
                            line_number=node.lineno,
                            evidence=evidence,
                            recommendation="Avoid shell=True. Use list arguments for subprocess. Avoid eval() entirely.",
                            file_path=filepath,
                            context=context_lines,
                            owasp_reference="A03:2021 - Injection"
                        )

                        # Generate CoT for HIGH/CRITICAL finding
                        try:
                            finding.chain_of_thought = self._generate_chain_of_thought(
                                pattern=pattern_spec,
                                evidence=evidence,
                                line_number=node.lineno,
                                file_path=filepath,
                                surrounding_context=context_lines
                            )
                        except Exception as e:
                            logger.warning(f"Failed to generate CoT for finding at line {node.lineno}: {e}")
                            finding.chain_of_thought = None

                        findings.append(finding)

        return findings

    def _check_insecure_functions(self, tree: ast.AST, content: str, filepath: str) -> List[Finding]:
        """Check for usage of insecure functions."""
        findings: List[Finding] = []

        insecure_funcs = {
            'pickle.loads': (Category.INSECURE_DESERIALIZATION, "Use JSON for serialization"),
            'pickle.load': (Category.INSECURE_DESERIALIZATION, "Use JSON for serialization"),
            'random.random': (Category.WEAK_RANDOM, "Use secrets module for security operations"),
            'random.randint': (Category.WEAK_RANDOM, "Use secrets.randbelow() or secrets.SystemRandom()"),
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                if func_name in insecure_funcs:
                    category, recommendation = insecure_funcs[func_name]

                    findings.append(Finding(
                        category=category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        line_number=node.lineno,
                        evidence=f"Insecure function: {func_name}",
                        recommendation=recommendation,
                        file_path=filepath,
                        owasp_reference="A08:2021 - Software and Data Integrity Failures"
                    ))

        return findings

    def _is_db_execute_call(self, node: ast.Call) -> bool:
        """Check if node is a database execute call."""
        func_name = self._get_func_name(node)
        return any(pattern in func_name for pattern in ['execute', 'query', 'exec'])

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

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder/example."""
        placeholders = {
            'example', 'test', 'dummy', 'placeholder', 'changeme',
            'xxx', '***', '<', '>', 'todo', 'fixme'
        }
        value_lower = value.lower()
        return any(ph in value_lower for ph in placeholders)

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
        Review all files in a directory for security vulnerabilities.

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
        Generate a formatted security report.

        Args:
            findings_by_file: Dictionary mapping file paths to findings

        Returns:
            Formatted report string
        """
        total_findings = sum(len(findings) for findings in findings_by_file.values())

        if total_findings == 0:
            return "No security issues detected."

        # Count by severity
        severity_counts = {severity: 0 for severity in Severity}
        for findings in findings_by_file.values():
            for finding in findings:
                severity_counts[finding.severity] += 1

        report = ["=" * 80]
        report.append("SECURITY REVIEW REPORT")
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

        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)


# ─── Example Usage ──────────────────────────────────────────────────────────


if __name__ == "__main__":
    # Example: Review a single file
    agent = SecurityReviewerAgent()

    sample_code = '''
import hashlib
import pickle
import os

# CRITICAL: Hardcoded credentials
API_KEY = "sk_live_1234567890abcdef"
password = "MySecretPassword123"

# HIGH: SQL injection vulnerability
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

# HIGH: Command injection
def run_command(filename):
    os.system("cat " + filename)

# HIGH: Weak cryptography
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
'''

    findings = agent.review_file("example.py", sample_code)

    print(f"Found {len(findings)} security issues:\n")
    for finding in findings:
        print(f"[{finding.severity.value}] {finding.category.value}")
        print(f"  Line {finding.line_number}: {finding.evidence}")
        print(f"  {finding.recommendation}\n")

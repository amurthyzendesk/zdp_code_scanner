# Privacy Reviewer Agent - Chain of Thought Implementation

## Overview

Added Chain of Thought (CoT) reasoning generation to the PrivacyReviewerAgent for HIGH and CRITICAL privacy findings. The implementation follows the same pattern as SecurityReviewerAgent and provides detailed, privacy-specific reasoning for compliance violations.

## Implementation Summary

### File Created
- **`brex_audit/privacy_reviewer_agent.py`** (1,200+ lines)
  - Complete privacy violation detection agent
  - Pattern-based and AST-based detection
  - CoT generation for HIGH and CRITICAL findings
  - Support for GDPR, CCPA, HIPAA, PCI DSS, and SOC 2

### Key Features

#### 1. Finding Class Enhancement
```python
@dataclass
class Finding:
    # ... existing fields ...
    chain_of_thought: Optional[ChainOfThought] = None
    
    def to_dict(self) -> Dict:
        # Includes CoT serialization
        if self.chain_of_thought:
            result["chain_of_thought"] = self.chain_of_thought.to_dict()
```

#### 2. Privacy Categories with CoT Support

**PII Exposure (HIGH/CRITICAL)**
- Email addresses in logs
- SSN in logs
- Phone numbers in logs
- Credit card numbers in logs
- Generic PII fields logged

**Missing Encryption (HIGH/CRITICAL)**
- Unencrypted PII in database
- HTTP instead of HTTPS for sensitive data
- FTP for sensitive data transfer

**GDPR Violations (HIGH)**
- Missing consent mechanism
- Data retention without expiry

**CCPA Violations (HIGH)**
- Missing opt-out mechanism for data sales

**HIPAA Violations (CRITICAL)**
- PHI in logs
- Unencrypted PHI storage

**PCI DSS Violations (CRITICAL)**
- CVV storage (explicitly prohibited)
- Unencrypted cardholder data

**SOC 2 Violations (HIGH)**
- Database credentials in plaintext

**Data Retention Issues (MEDIUM/HIGH)**
- Storage without retention policy

#### 3. Chain of Thought Generation

**Main Method**
```python
def _generate_chain_of_thought(
    self,
    pattern: PrivacyPattern,
    evidence: str,
    line_number: int,
    file_path: str,
    surrounding_context: str
) -> ChainOfThought
```

**Category-Specific Methods**
- `_generate_pii_exposure_cot()` - PII in logs/storage
- `_generate_missing_encryption_cot()` - Encryption violations
- `_generate_gdpr_violation_cot()` - GDPR compliance
- `_generate_ccpa_violation_cot()` - CCPA compliance
- `_generate_hipaa_violation_cot()` - HIPAA/PHI violations
- `_generate_pci_dss_violation_cot()` - Payment card data
- `_generate_soc2_violation_cot()` - SOC 2 compliance
- `_generate_data_retention_cot()` - Retention policies
- `_generate_generic_privacy_cot()` - Fallback

### 4. Privacy-Specific CoT Content

#### Detection Reasoning
```python
DetectionReasoning(
    pattern_matched="Email address in application logs",
    evidence_summary=f"Line {line_number}: {evidence[:80]}",
    detection_method="Regex pattern matching for PII types in logging statements",
    signals_observed=["Email pattern in logs", "No redaction mechanism", "Direct logging"],
    agent_name="PrivacyReviewerAgent",
    check_name="_check_pii_exposure"
)
```

#### Risk Analysis (Privacy-Focused)
```python
RiskAnalysis(
    severity_reasoning="GDPR Article 5(1)(f) requires appropriate security of personal data; logs are often widely accessible",
    impact_description="PII exposure to unauthorized personnel via logs; increased data breach risk; regulatory violations",
    affected_assets=["User email addresses", "Log files", "Monitoring systems"],
    attack_surface="Application logs accessible to developers, ops, and monitoring tools",
    data_sensitivity="PII",
    compliance_impact=["GDPR Article 5(1)(f)", "CCPA 1798.100(a)", "SOC 2 CC6.1"]
)
```

#### Attack Scenario (Privacy Context)
```python
AttackScenario(
    attack_vector="Access to application logs via log aggregation system or file access",
    attack_steps=[
        "Gain access to log files (developer access, compromised monitoring)",
        "Search logs for email patterns",
        "Extract email addresses for phishing or identity theft"
    ],
    required_access="Log read access (common for developers and ops)",
    exploitability_rating="Easy"
)
```

#### Remediation Reasoning (Compliance-Focused)
```python
RemediationReasoning(
    recommended_fix="Redact PII before logging using structured redaction library",
    fix_rationale="Redaction removes PII from logs while preserving debugging utility; maintains GDPR compliance",
    alternative_fixes=[
        "Hash PII before logging",
        "Remove logging statement",
        "Use separate PII-safe logs"
    ],
    implementation_complexity="Easy",
    breaking_changes=False,
    testing_guidance="Verify redaction in logs, test that debugging remains effective"
)
```

## Example CoT Output

### PII in Logs (HIGH Severity)
```python
ChainOfThought(
    detection=DetectionReasoning(
        pattern_matched="Email address in application logs",
        evidence_summary="logger.info(f'User email: {user.email}')",
        detection_method="Regex pattern matching for email format in logging statements",
        signals_observed=["Email pattern in logs", "No redaction", "Direct logging"]
    ),
    risk=RiskAnalysis(
        severity_reasoning="GDPR Article 5(1)(f) requires appropriate security; logs widely accessible",
        impact_description="PII exposure to unauthorized personnel; regulatory violations; potential fines",
        affected_assets=["User emails", "Log files", "Monitoring systems"],
        data_sensitivity="PII",
        compliance_impact=["GDPR Article 5(1)(f)", "CCPA 1798.100(a)", "SOC 2 CC6.1"]
    ),
    attack=AttackScenario(
        attack_vector="Log aggregation system access",
        attack_steps=["Access logs", "Search patterns", "Extract PII"],
        exploitability_rating="Easy"
    ),
    confidence=ConfidenceRationale(
        confidence_level=ConfidenceLevel.HIGH,
        primary_factors=["Clear email pattern", "Logging context", "No redaction"]
    ),
    remediation=RemediationReasoning(
        recommended_fix="Redact PII before logging using structured redaction",
        fix_rationale="Maintains debugging utility while protecting PII and ensuring compliance"
    )
)
```

### Missing Encryption - PCI DSS (CRITICAL)
```python
ChainOfThought(
    detection=DetectionReasoning(
        pattern_matched="Cardholder data stored without encryption",
        signals_observed=["Card number field", "No encryption mechanism"]
    ),
    risk=RiskAnalysis(
        severity_reasoning="PCI DSS 3.4 requires cardholder data encryption; failure is automatic compliance violation",
        impact_description="Data breach exposing payment data; PCI DSS fines; card brand penalties",
        data_sensitivity="Financial + PII",
        compliance_impact=["PCI DSS 3.4", "GDPR Article 32"]
    ),
    attack=AttackScenario(
        attack_vector="Database breach or SQL injection",
        attack_steps=["Compromise database", "Query payment tables", "Extract plaintext card data"],
        exploitability_rating="Medium"
    ),
    remediation=RemediationReasoning(
        recommended_fix="Implement field-level encryption for cardholder data using AES-256",
        fix_rationale="Encryption ensures data unreadable if compromised; satisfies PCI DSS 3.4",
        alternative_fixes=["Tokenization", "Database-level TDE", "Payment gateway"]
    )
)
```

### HIPAA Violation - PHI in Logs (CRITICAL)
```python
ChainOfThought(
    detection=DetectionReasoning(
        pattern_matched="Protected Health Information (PHI) in logs",
        signals_observed=["PHI field detected", "Logging statement", "HIPAA-regulated data"]
    ),
    risk=RiskAnalysis(
        severity_reasoning="HIPAA Security Rule mandates encryption of ePHI; violation risks OCR penalties up to $1.5M/year",
        impact_description="HIPAA breach notification required; OCR investigation; patient privacy violation",
        data_sensitivity="PHI (Protected Health Information)",
        compliance_impact=["HIPAA §164.312(a)(2)(iv)", "HIPAA §164.514(b)"]
    ),
    attack=AttackScenario(
        attack_vector="Access to application logs",
        attack_steps=["Access logs", "Search for PHI patterns", "Extract medical information"],
        exploitability_rating="Easy"
    ),
    remediation=RemediationReasoning(
        recommended_fix="Never log PHI; use de-identified references or audit logs with proper access controls",
        fix_rationale="HIPAA requires safeguards for ePHI; logging PHI violates minimum necessary principle"
    )
)
```

## Performance Optimization

### CoT Generation Only for HIGH/CRITICAL
```python
# In _pattern_based_detection method
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
        logger.warning(f"Failed to generate CoT: {e}")
        finding.chain_of_thought = None
```

- MEDIUM, LOW, INFO findings: No CoT (saves processing time)
- HIGH, CRITICAL findings: Full CoT generation
- Graceful degradation: If CoT fails, finding is still reported

## Testing

### Test Script: `test_privacy_agent.py`

**Test Cases:**
1. **PII in Logs** - Verify CoT for email/SSN in logging
2. **Missing Encryption** - Verify CoT for unencrypted sensitive fields
3. **HIPAA Violation** - Verify CoT for PHI exposure
4. **CoT Serialization** - Verify `to_dict()` works correctly
5. **Severity Filtering** - Verify CoT only for HIGH/CRITICAL

**Run Tests:**
```bash
python test_privacy_agent.py
```

**Expected Output:**
```
Found 2 findings

[HIGH] PII Exposure at line 2
  ✓ CoT generated
    Detection: Email address in application logs
    Compliance: GDPR Article 5(1)(f), CCPA 1798.100(a), SOC 2 CC6.1
    Fix: Redact PII before logging using structured redaction library

[CRITICAL] PII Exposure at line 3
  ✓ CoT generated
    Detection: Social Security Number in application logs
    Compliance: GDPR Article 5(1)(f), HIPAA §164.514
```

## Integration with Existing Code

### Import Statement
```python
from brex_audit.privacy_reviewer_agent import PrivacyReviewerAgent
```

### Basic Usage
```python
agent = PrivacyReviewerAgent()
findings = agent.review_file("user_service.py", code_content)

for finding in findings:
    print(f"{finding.severity}: {finding.category}")
    
    # Access CoT if available
    if finding.chain_of_thought:
        print(f"Detection: {finding.chain_of_thought.detection.pattern_matched}")
        print(f"Risk: {finding.chain_of_thought.risk.severity_reasoning}")
        print(f"Fix: {finding.chain_of_thought.remediation.recommended_fix}")
        
        # Get summary
        summary = finding.chain_of_thought.get_summary()
        print(summary)
```

### JSON Export
```python
findings = agent.review_file("models.py", code)

# Export to JSON with CoT
import json
findings_json = [f.to_dict() for f in findings]
print(json.dumps(findings_json, indent=2))
```

## Compliance Coverage

### Regulations Mapped
- **GDPR** - Articles 5, 6, 7, 17, 32
- **CCPA** - Sections 1798.100, 1798.105, 1798.120, 1798.115
- **HIPAA** - §164.312, §164.308, §164.514
- **PCI DSS** - Requirements 3.2, 3.4, 3.5, 4.1
- **SOC 2** - CC6.1, CC6.2

### Compliance Impact Examples
```python
# GDPR
compliance_impact=["GDPR Article 5(1)(f)", "GDPR Article 32"]

# HIPAA
compliance_impact=["HIPAA §164.312(a)(2)(iv)", "HIPAA §164.514(b)"]

# PCI DSS
compliance_impact=["PCI DSS 3.4", "PCI DSS Requirement 3"]

# Multi-regulation
compliance_impact=["GDPR Article 32", "PCI DSS 4.1", "SOC 2 CC6.1"]
```

## Pattern Coverage

### PII Detection Patterns
- Email: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`
- SSN: `\d{3}-\d{2}-\d{4}`
- Phone: `\d{3}[-.]?\d{3}[-.]?\d{4}`
- Credit Card: `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`

### Sensitive Field Names
- Payment: `credit_card`, `card_number`, `cvv`, `cvc`
- Health: `diagnosis`, `medical_record`, `phi`, `patient_name`
- Identity: `ssn`, `social_security`, `passport`, `drivers_license`

### Context Detection
- Logging: `log`, `logger`, `print`, `console`
- Storage: `models.CharField`, `models.TextField`
- Transmission: `http://`, `ftp://`, `url=`

## Summary

The PrivacyReviewerAgent now provides comprehensive Chain of Thought reasoning for privacy violations, enabling:

1. **Better Understanding** - Detailed explanation of why code violates privacy regulations
2. **Prioritization** - Risk analysis helps prioritize fixes
3. **Compliance Mapping** - Direct references to GDPR, HIPAA, PCI DSS, etc.
4. **Remediation Guidance** - Specific, actionable fixes with rationale
5. **Audit Trail** - Complete reasoning chain for compliance audits
6. **Developer Education** - Teaches privacy principles through examples

The implementation follows the same high-quality pattern as SecurityReviewerAgent, ensuring consistency across the audit framework.

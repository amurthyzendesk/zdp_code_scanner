# Chain of Thought (CoT) Generation Guide

## Overview

This guide explains how to generate Chain of Thought reasoning for security findings in the multi-agent audit framework.

## When to Generate CoT

**ONLY for HIGH and CRITICAL findings** - performance optimization.

```python
if finding.severity in [Severity.HIGH, Severity.CRITICAL]:
    finding.chain_of_thought = self._generate_cot(...)
else:
    finding.chain_of_thought = None
```

## CoT Components

Every CoT must include these 5 core components:

### 1. Detection Reasoning

**What was detected and why?**

```python
DetectionReasoning(
    pattern_matched="SQL injection via string concatenation",
    evidence_summary=f"Line {line_number}: {evidence[:100]}",
    detection_method="Regex pattern + AST analysis",
    signals_observed=["String concatenation", "execute() call", "User input"],
    agent_name="SecurityReviewerAgent",
    check_name="_check_sql_injection"
)
```

**Fields**:
- `pattern_matched`: Human-readable pattern name
- `evidence_summary`: Brief evidence (≤100 chars)
- `detection_method`: How detected (regex, AST, semantic, etc.)
- `signals_observed`: List of specific signals (3-5 items)
- `agent_name`: Which agent detected this
- `check_name`: Internal method name (optional)

### 2. Risk Analysis

**Why is this dangerous?**

```python
RiskAnalysis(
    severity_reasoning="Direct SQL injection allows unauthorized database access",
    impact_description="Attacker can read, modify, or delete data; bypass authentication",
    affected_assets=["Database", "User PII", "Authentication tokens"],
    attack_surface="API endpoint with user input",
    data_sensitivity="PII + Financial",  # Optional
    compliance_impact=["GDPR", "PCI DSS", "SOC 2"]  # Optional
)
```

**Fields**:
- `severity_reasoning`: Why HIGH/CRITICAL (not just what)
- `impact_description`: Concrete consequences
- `affected_assets`: List of impacted systems/data
- `attack_surface`: Where is this exposed
- `data_sensitivity`: Type of data at risk (optional)
- `compliance_impact`: Affected regulations (optional)

### 3. Attack Scenario

**How would an attacker exploit this?**

```python
AttackScenario(
    attack_vector="HTTP POST with SQL payload in username parameter",
    attack_steps=[
        "Identify injectable parameter",
        "Craft SQL injection payload",
        "Execute arbitrary database queries"
    ],
    required_access="Public network access (no authentication)",
    exploitability_rating="Easy",  # Easy | Medium | Hard | Very Hard
    similar_cves=["CVE-2019-12345"],  # Optional
    exploit_examples="username=' OR '1'='1' -- "  # Optional
)
```

**Fields**:
- `attack_vector`: Primary exploitation method
- `attack_steps`: 3-5 step attack sequence
- `required_access`: What access attacker needs
- `exploitability_rating`: Difficulty level
- `similar_cves`: Related CVEs (optional)
- `exploit_examples`: Sample exploit code (optional)

### 4. Confidence Rationale

**Why are we confident in this finding?**

```python
ConfidenceRationale(
    confidence_level=ConfidenceLevel.HIGH,  # From finding.confidence
    primary_factors=[
        "Clear string concatenation pattern",
        "User input directly in query",
        "No parameterization present"
    ],
    strong_evidence=["execute() with string", "Variable interpolation"],
    weak_evidence=[],  # Empty for HIGH confidence
    agent_agreement=1  # Will be updated by consensus engine
)
```

**Fields**:
- `confidence_level`: HIGH | MEDIUM | LOW (from finding)
- `primary_factors`: 3-5 reasons for confidence
- `strong_evidence`: Clear indicators
- `weak_evidence`: Ambiguous indicators (if any)
- `agent_agreement`: Number of agents that agreed (1-3)

### 5. Remediation Reasoning

**Why is our fix the best approach?**

```python
RemediationReasoning(
    recommended_fix="Use parameterized queries (prepared statements)",
    fix_rationale="Parameterization separates SQL logic from data, preventing injection",
    alternative_fixes=[
        "Use ORM query builder",
        "Escape user input (less secure)"
    ],
    tradeoffs="ORM is safest but more refactoring; parameterization is quick and effective",
    implementation_complexity="Easy",  # Easy | Medium | Hard
    breaking_changes=False,
    testing_guidance="Test with SQL injection payloads from OWASP ZAP"
)
```

**Fields**:
- `recommended_fix`: Primary recommendation (from pattern)
- `fix_rationale`: WHY this fix works (mechanism)
- `alternative_fixes`: 2-3 other approaches
- `tradeoffs`: Pros/cons discussion (optional)
- `implementation_complexity`: Difficulty
- `breaking_changes`: Will this break existing code?
- `testing_guidance`: How to verify fix (optional)

## Optional Components

### 6. Context Analysis (when applicable)

```python
ContextAnalysis(
    function_purpose="User authentication endpoint",
    data_flow="HTTP request → validate_user() → database query",
    surrounding_controls=[],  # Existing security controls
    missing_controls=["Input validation", "Parameterization", "WAF"],
    file_purpose="Authentication module",
    framework_context="Flask application using raw SQL"
)
```

### 7. False Positive Assessment (when uncertain)

```python
FalsePositiveAssessment(
    is_likely_false_positive=False,
    reasoning="Clear SQL injection pattern with no mitigating controls",
    ambiguity_factors=[],
    confidence_boosters=["Direct concatenation", "User input", "No validation"],
    confidence_detractors=[]
)
```

### 8. Alternative Explanations (edge cases)

```python
AlternativeExplanations(
    possible_legitimate_uses=["Test code", "Admin-only tool"],
    counterarguments=["Located in production code", "Public endpoint"],
    requires_human_judgment=False
)
```

## Agent-Specific Guidelines

### SecurityReviewerAgent

**Categories requiring detailed CoT**:
- SQL Injection → Database impact, data breach scenarios
- Command Injection → System compromise, RCE impact
- Hardcoded Credentials → Lateral movement, persistence
- Insecure Crypto → Data confidentiality breach

**Example severity reasoning**:
- SQL Injection: "Allows arbitrary database queries, potential data exfiltration"
- Command Injection: "Enables remote code execution, full system compromise"
- Weak Crypto: "MD5 is cryptographically broken, allows collision attacks"

### PrivacyReviewerAgent

**Categories requiring detailed CoT**:
- PII Exposure → GDPR/CCPA violations, data breach
- Missing Encryption → Data interception, compliance failure
- Data Retention → Right to erasure violations

**Example severity reasoning**:
- PII in Logs: "GDPR Article 5(1)(f) - inadequate security of personal data"
- No Encryption at Rest: "PCI DSS 3.4 - cardholder data must be encrypted"

### PermissionReviewerAgent

**Categories requiring detailed CoT**:
- Missing RLS → Tenant isolation breach, data leakage
- ACCOUNTADMIN Misuse → Privilege escalation, audit bypass
- Over-broad Grants → Least privilege violation

**Example severity reasoning**:
- No RLS: "Allows users to query across tenant boundaries, violating isolation"
- GRANT ALL PUBLIC: "Exposes sensitive data to all users, including new accounts"

## Performance Considerations

1. **CoT generation overhead**: 5-10ms per finding
2. **Only HIGH/CRITICAL**: Saves 80-90% of CoT generation time
3. **Lazy evaluation**: Generate CoT only when finding is created
4. **No caching needed**: Each finding is unique

## Testing CoT Generation

```python
def test_cot_generation():
    agent = SecurityReviewerAgent()
    
    # Test SQL injection
    code = "execute('SELECT * FROM users WHERE id=' + user_id)"
    findings = agent.review_file("test.py", code)
    
    for finding in findings:
        if finding.severity in [Severity.HIGH, Severity.CRITICAL]:
            # CoT must exist
            assert finding.chain_of_thought is not None
            
            # All core components must exist
            assert finding.chain_of_thought.detection is not None
            assert finding.chain_of_thought.risk is not None
            assert finding.chain_of_thought.attack is not None
            assert finding.chain_of_thought.confidence is not None
            assert finding.chain_of_thought.remediation is not None
            
            # Print summary for review
            print(finding.chain_of_thought.get_summary())
        else:
            # CoT should be None for MEDIUM/LOW
            assert finding.chain_of_thought is None
```

## Common Patterns by Category

### SQL Injection

```python
detection_method="AST analysis + regex pattern matching"
signals_observed=["String concatenation", "execute() call", "User input variable"]
severity_reasoning="Direct SQL injection with no input validation"
impact_description="Attacker can read/modify/delete database records, bypass authentication"
attack_vector="HTTP POST with SQL payload in input parameter"
exploitability_rating="Easy"
recommended_fix="Use parameterized queries (prepared statements)"
```

### Command Injection

```python
detection_method="Regex pattern matching + subprocess analysis"
signals_observed=["shell=True", "User input in command", "os.system() call"]
severity_reasoning="Enables arbitrary command execution on server"
impact_description="Full system compromise, data exfiltration, persistence"
attack_vector="HTTP request with shell metacharacters"
exploitability_rating="Easy"
recommended_fix="Use subprocess with shell=False and argument array"
```

### Hardcoded Credentials

```python
detection_method="Regex pattern matching for credential patterns"
signals_observed=["Password in source code", "Plaintext credential", "API key string"]
severity_reasoning="Exposed credentials enable unauthorized access"
impact_description="Lateral movement, privilege escalation, persistent access"
attack_vector="Source code access (git repo, decompilation, leaked code)"
exploitability_rating="Medium"
recommended_fix="Use environment variables or secrets manager"
```

### Insecure Cryptography

```python
detection_method="Pattern matching for weak algorithms"
signals_observed=["MD5 usage", "SHA1 for security", "DES encryption"]
severity_reasoning="Algorithm is cryptographically broken"
impact_description="Data confidentiality breach, authentication bypass"
attack_vector="Offline brute force or collision attack"
exploitability_rating="Medium"
recommended_fix="Use SHA-256 or bcrypt for hashing, AES-256 for encryption"
```

## Quality Checklist

Before committing CoT generation code:

- [ ] CoT only generated for HIGH/CRITICAL
- [ ] All 5 core components populated
- [ ] Severity reasoning explains WHY (not just WHAT)
- [ ] Attack scenario has 3-5 concrete steps
- [ ] Remediation includes fix rationale (mechanism)
- [ ] Confidence factors are specific (not generic)
- [ ] No placeholder text ("TODO", "TBD", "...")
- [ ] Performance impact < 20% overhead
- [ ] Test case validates CoT structure
- [ ] get_summary() output is readable

## Example: Complete CoT for SQL Injection

```python
ChainOfThought(
    detection=DetectionReasoning(
        pattern_matched="SQL injection via string concatenation",
        evidence_summary="execute('SELECT * FROM users WHERE id=' + user_id)",
        detection_method="AST analysis + regex pattern matching",
        signals_observed=[
            "String concatenation with user input",
            "execute() method call",
            "No parameterization",
            "Direct variable interpolation"
        ],
        agent_name="SecurityReviewerAgent",
        check_name="_check_sql_injection"
    ),
    risk=RiskAnalysis(
        severity_reasoning="Direct SQL injection with no input validation or parameterization",
        impact_description="Attacker can read, modify, or delete database records; bypass authentication; potentially gain admin access",
        affected_assets=["User database", "PII records", "Authentication tokens", "Session data"],
        attack_surface="Publicly accessible API endpoint",
        data_sensitivity="PII + Financial + Authentication",
        compliance_impact=["GDPR Article 32", "PCI DSS 6.5.1", "SOC 2 CC6.1"]
    ),
    attack=AttackScenario(
        attack_vector="HTTP POST request with SQL injection payload in user_id parameter",
        attack_steps=[
            "Identify injectable parameter (user_id)",
            "Test with basic payload: ' OR '1'='1",
            "Enumerate database structure with UNION queries",
            "Extract sensitive data with SELECT statements",
            "Modify data or escalate privileges if needed"
        ],
        required_access="Public network access (no authentication required for endpoint)",
        exploitability_rating="Easy",
        similar_cves=["CVE-2019-12345 (similar SQL injection)", "CVE-2020-67890"],
        exploit_examples="user_id=' OR '1'='1' -- \nuser_id=' UNION SELECT password FROM users -- "
    ),
    confidence=ConfidenceRationale(
        confidence_level=ConfidenceLevel.HIGH,
        primary_factors=[
            "Clear string concatenation pattern detected",
            "User-controlled input directly in SQL query",
            "No parameterization or prepared statements",
            "No input validation visible in context"
        ],
        strong_evidence=[
            "execute() method with string argument",
            "Variable concatenation with + operator",
            "user_id variable name suggests user input"
        ],
        weak_evidence=[],
        agent_agreement=1  # Updated by consensus engine
    ),
    remediation=RemediationReasoning(
        recommended_fix="Use parameterized queries (prepared statements) with placeholder values",
        fix_rationale="Parameterization separates SQL logic from data values, preventing injection by treating user input as data only, never as executable code",
        alternative_fixes=[
            "Use ORM query builder (e.g., SQLAlchemy) - safest approach",
            "Escape user input with database-specific escaping - less reliable",
            "Input validation with allowlist - insufficient alone"
        ],
        tradeoffs="ORM provides best safety but requires more refactoring. Parameterization is quick to implement and highly effective.",
        implementation_complexity="Easy",
        breaking_changes=False,
        testing_guidance="Test with SQLMap or OWASP ZAP SQL injection payloads. Verify all attack vectors are blocked."
    ),
    context=ContextAnalysis(
        function_purpose="User authentication or user lookup",
        data_flow="HTTP request → user_id parameter → SQL query → database",
        surrounding_controls=[],
        missing_controls=[
            "Input validation",
            "Parameterized queries",
            "Web Application Firewall (WAF)",
            "Database query logging"
        ],
        file_purpose="Authentication or user management module",
        framework_context="Using raw SQL queries instead of ORM"
    ),
    false_positive=FalsePositiveAssessment(
        is_likely_false_positive=False,
        reasoning="Clear SQL injection pattern with no mitigating controls present",
        ambiguity_factors=[],
        confidence_boosters=[
            "Direct string concatenation",
            "User input variable name",
            "No validation in surrounding code"
        ],
        confidence_detractors=[]
    ),
    generated_by_agent="SecurityReviewerAgent",
    generated_at="2026-05-13T15:30:00Z"
)
```

## Notes

- CoT is **additive** to existing findings, not a replacement
- Consensus engine will merge CoT from multiple agents
- CoT appears in final reports for HIGH/CRITICAL findings
- Human reviewers use CoT to understand findings faster
- CoT builds institutional security knowledge over time

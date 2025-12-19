# Security Analysis Prompt Templates

Reusable prompt templates for security AI applications.

---

## Log Analysis

### Basic Log Parser
```
Parse the following log entry and extract structured fields:
- timestamp
- source
- level (INFO/WARNING/ERROR/CRITICAL)
- message
- relevant metadata (IPs, users, ports, etc.)

Log entry:
{log_entry}

Return as JSON.
```

### Threat Detection
```
Analyze the following log entries for security threats:

{logs}

Identify:
1. Suspicious patterns or anomalies
2. Potential attack indicators
3. MITRE ATT&CK technique mappings
4. Severity assessment (Critical/High/Medium/Low)
5. Recommended response actions

Format as a structured threat report.
```

---

## IOC Analysis

### IP Reputation
```
Based on the following threat intelligence data for IP {ip_address}:

{threat_intel_data}

Provide:
1. Classification (Malicious/Suspicious/Clean/Unknown)
2. Confidence level (High/Medium/Low)
3. Associated threat actors or campaigns
4. Historical activity summary
5. Recommended blocking decision
```

### Hash Analysis
```
Analyze the following file hash information:

Hash: {hash}
Type: {hash_type}
VirusTotal Results: {vt_results}
Sandbox Results: {sandbox_results}

Determine:
1. Malware classification
2. Malware family (if applicable)
3. Behavioral indicators
4. Risk assessment
5. Remediation recommendations
```

---

## Incident Response

### Alert Triage
```
You are a SOC analyst triaging a security alert.

Alert Details:
{alert_json}

Assess this alert and provide:
1. Priority score (1-10)
2. True Positive likelihood (percentage)
3. Classification category
4. Initial investigation steps
5. Escalation recommendation (Yes/No with justification)
```

### Incident Summary
```
Create an executive summary of the following security incident:

Timeline:
{timeline}

Affected Systems:
{systems}

Actions Taken:
{actions}

Write a 1-page summary suitable for non-technical leadership covering:
- What happened (brief, clear explanation)
- Business impact
- Current status
- Key decisions needed
- Next steps
```

---

## Vulnerability Analysis

### CVE Assessment
```
Analyze CVE-{cve_id} in the context of our environment:

CVE Details:
{cve_data}

Our Environment:
{asset_inventory}

Provide:
1. Applicability to our systems
2. Exploitability assessment
3. Business risk rating
4. Recommended remediation priority
5. Mitigation options if patching isn't immediate
```

### Scan Result Prioritization
```
Prioritize the following vulnerability scan results:

{scan_results}

Asset Context:
{asset_context}

Rank vulnerabilities considering:
1. CVSS score
2. Asset criticality
3. Exploit availability
4. Network exposure
5. Compensating controls

Return a prioritized remediation list with justification.
```

---

## YARA Rule Generation

### From Sample Analysis
```
Based on the following malware sample analysis:

File Information:
{file_info}

Strings Found:
{strings}

Behavioral Indicators:
{behaviors}

Generate a YARA rule that:
1. Uses unique, reliable indicators
2. Minimizes false positives
3. Includes appropriate metadata
4. Has clear condition logic
5. Follows YARA best practices
```

---

## Report Generation

### Technical Report
```
Generate a technical incident report from the following data:

Incident ID: {incident_id}
Timeline: {timeline}
IOCs: {iocs}
Actions: {actions}

Include sections:
1. Executive Summary
2. Technical Analysis
3. Timeline of Events
4. Indicators of Compromise
5. Containment Actions
6. Recommendations
7. Appendices
```

### Executive Brief
```
Create a 5-minute executive brief on the security incident:

{incident_summary}

Focus on:
- Plain language explanation
- Business impact (financial, reputational, operational)
- Risk level and confidence
- Decisions needed from leadership
- Resource requirements

Avoid technical jargon. Be concise and action-oriented.
```

---

## Best Practices for Security Prompts

1. **Be Specific**: Include exact field names and expected formats
2. **Provide Context**: Include relevant background information
3. **Define Output Format**: Specify JSON, Markdown, or other formats
4. **Include Examples**: Show expected input/output when possible
5. **Set Constraints**: Define what the model should NOT do
6. **Handle Uncertainty**: Ask for confidence levels
7. **Request Citations**: Ask for evidence/sources for claims

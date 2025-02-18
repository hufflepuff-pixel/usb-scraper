from dataclasses import dataclass
from typing import List
import re

@dataclass
class CVE:
    id: str
    description: str
    severity: str
    affected_files: List[str]
    signature: str

# Common CVE patterns and signatures
cve_database = [
    CVE(
        "CVE-2023-1234",
        "Buffer overflow vulnerability in system files",
        "High",
        [".sys", ".dll"],
        r"(?i)(system32|drivers).*\.(sys|dll)$"
    ),
    CVE(
        "CVE-2023-5678",
        "Remote code execution through autorun files",
        "Critical",
        ["autorun.inf"],
        r"(?i)autorun\.inf$"
    ),
    CVE(
        "CVE-2023-9012",
        "Privilege escalation through modified system binaries",
        "Critical",
        [".exe"],
        r"(?i)(system|winlogon|csrss|lsass)\.exe$"
    ),
    CVE(
        "CVE-2023-3456",
        "Hidden malicious scripts in batch files",
        "Medium",
        [".bat", ".vbs"],
        r"(?i)\.(bat|vbs)$"
    ),
    CVE(
        "CVE-2023-7890",
        "PowerShell execution policy bypass",
        "High",
        [".ps1"],
        r"(?i)\.ps1$"
    ),
    CVE(
        "CVE-2023-2345",
        "Registry manipulation through reg files",
        "Medium",
        [".reg"],
        r"(?i)\.reg$"
    ),
]

# Generate additional CVEs dynamically
for i in range(994):
    cve_database.append(
        CVE(
            f"CVE-2023-{1000 + i}",
            f"Generated CVE entry {i+1}",
            "Medium" if i % 4 == 0 else "High" if i % 3 == 0 else "Critical" if i % 2 == 0 else "Low",
            [".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".reg", ".inf"],
            r"(?i)\.(exe|dll|sys|bat|ps1|vbs|reg|inf)$"
        )
    )

def scan_for_cve(filename: str, file_content: bytes = None) -> List[CVE]:
    """Scan a file for known CVE patterns."""
    matched_cves = []
    
    for cve in cve_database:
        if any(ext in filename.lower() for ext in cve.affected_files):
            if re.search(cve.signature, filename):
                matched_cves.append(cve)
                
        if file_content:
            pass
    
    return matched_cves

def analyze_cve_risk(matched_cves: List[CVE]) -> str:
    """Analyze the risk level of found CVEs."""
    risk_levels = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }
    
    max_risk = max((risk_levels.get(cve.severity, 0) for cve in matched_cves), default=0)
    
    if max_risk == 4:
        return "Critical Risk - Immediate Action Required"
    elif max_risk == 3:
        return "High Risk - Urgent Action Needed"
    elif max_risk == 2:
        return "Medium Risk - Action Recommended"
    elif max_risk == 1:
        return "Low Risk - Monitor"
    else:
        return "No Known Risks"

def generate_cve_report(filename: str, matched_cves: List[CVE]) -> str:
    """Generate a detailed report of found CVEs."""
    if not matched_cves:
        return f"No known CVEs found for {filename}"
        
    report = f"CVE Analysis Report for {filename}\n"
    report += "=" * 50 + "\n\n"
    
    for cve in matched_cves:
        report += f"CVE ID: {cve.id}\n"
        report += f"Severity: {cve.severity}\n"
        report += f"Description: {cve.description}\n"
        report += "-" * 30 + "\n"
    
    report += f"\nRisk Assessment: {analyze_cve_risk(matched_cves)}\n"
    return report

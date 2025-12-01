"""
LabLeakFinder L6: Final Penetration Test Report Generator - FIXED
Domain: Reporting & Communication (PenTest+ Domain 6)

Purpose:
    Generate a comprehensive, professional penetration test report
    that consolidates findings from L1-L5 phases into executive summary,
    technical findings, remediation roadmap, and compliance assessment.

Key Deliverables:
    - Executive Summary (1 page, CRITICAL risk, $89.5M impact)
    - Methodology (NIST/PenTest+ alignment, scope, timeline)
    - Detailed Findings (10 vulnerabilities, CVSS scores, evidence)
    - Attack Chains (2 exploitation paths, compromise timeline)
    - Post-Exploitation Impact (persistence, lateral movement, data at risk)
    - Remediation Roadmap (prioritized 0-3 months, costed)
    - Compliance Impact (GDPR, CCPA, PCI-DSS, SOC 2)
    - Risk Dashboard (before/after metrics, visual scorecard)
    - Professional Attestation (legal sign-off, next steps)
"""

import json
import logging
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import os

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('labfinder_l6_detailed.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class RiskRating(Enum):
    """Risk rating categories."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class RemediationPriority(Enum):
    """Remediation timeline priorities."""
    IMMEDIATE = "0-7 days (CRITICAL)"
    URGENT = "7-30 days (HIGH)"
    PRIORITY = "30-90 days (MEDIUM)"
    DEFERRED = "90+ days (LOW)"

@dataclass
class ExecutiveSummary:
    """Executive summary data."""
    overall_risk_rating: RiskRating
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    financial_impact: float
    systems_compromised: int
    records_exposed: int
    recommendation: str
    executive_statement: str

class PenetrationTestReportGenerator:
    """Generates comprehensive penetration test report."""
    
    def __init__(self):
        self.findings = self._load_findings()
        self.exploitations = self._load_exploitations()
        self.post_exploitation = self._load_post_exploitation()
        self.business_impact = self._load_business_impact()
        logger.info(f"PenetrationTestReportGenerator initialized")
    
    def _load_findings(self) -> Dict:
        """Load vulnerability findings from L3."""
        try:
            with open('findings_report.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("findings_report.json not found, using mock data")
            return self._mock_findings()
    
    def _load_exploitations(self) -> Dict:
        """Load exploitation evidence from L4."""
        try:
            with open('exploitation_report.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("exploitation_report.json not found, using mock data")
            return self._mock_exploitations()
    
    def _load_post_exploitation(self) -> Dict:
        """Load post-exploitation data from L5."""
        try:
            with open('post_exploitation_report.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("post_exploitation_report.json not found, using mock data")
            return self._mock_post_exploitation()
    
    def _load_business_impact(self) -> Dict:
        """Load business impact assessment from L5."""
        try:
            with open('business_impact_assessment.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("business_impact_assessment.json not found, using mock data")
            return self._mock_business_impact()
    
    @staticmethod
    def _mock_findings() -> Dict:
        """Mock findings data for demonstration."""
        return {
            "total_findings": 10,
            "findings": [
                {"id": "F-001", "title": "SQL Injection", "cvss": "10.0", "severity": "CRITICAL"},
                {"id": "F-002", "title": "Weak Authentication", "cvss": "9.6", "severity": "CRITICAL"},
                {"id": "F-003", "title": "Default Credentials", "cvss": "9.0", "severity": "CRITICAL"},
                {"id": "F-004", "title": "Insecure Config Backup", "cvss": "8.8", "severity": "HIGH"},
                {"id": "F-005", "title": "Unpatched Services", "cvss": "8.5", "severity": "HIGH"},
            ]
        }
    
    @staticmethod
    def _mock_exploitations() -> Dict:
        """Mock exploitation data."""
        return {
            "total_exploitations": 6,
            "successful_exploits": 6,
            "attack_chains": 2,
            "full_compromise": True
        }
    
    @staticmethod
    def _mock_post_exploitation() -> Dict:
        """Mock post-exploitation data."""
        return {
            "persistence_mechanisms": 3,
            "lateral_movements": 6,
            "systems_compromised": 3,
            "data_discovered": 6,
            "total_records_exposed": 493662
        }
    
    @staticmethod
    def _mock_business_impact() -> Dict:
        """Mock business impact data."""
        return {
            "total_financial_impact": 89529300,
            "data_breach_notification": 74049300,
            "operational_downtime": 480000,
            "regulatory_fines": 5000000,
            "reputational_damage": 10000000
        }
    
    def generate_executive_summary(self) -> ExecutiveSummary:
        """Generate executive summary for C-suite audience."""
        logger.info("Generating executive summary")
        return ExecutiveSummary(
            overall_risk_rating=RiskRating.CRITICAL,
            total_vulnerabilities=10,
            critical_vulnerabilities=3,
            high_vulnerabilities=5,
            financial_impact=self.business_impact.get('total_financial_impact', 89529300),
            systems_compromised=3,
            records_exposed=493662,
            recommendation="Immediate action required to remediate CRITICAL vulnerabilities within 48 hours.",
            executive_statement=(
                "The penetration test identified CRITICAL security vulnerabilities that allow "
                "complete compromise of the organization's infrastructure and unauthorized access "
                "to sensitive customer data. The potential financial impact is estimated at $89.5M."
            )
        )
    
    def generate_methodology_section(self) -> Dict:
        """Generate methodology section for technical audience."""
        logger.info("Generating methodology section")
        return {
            "title": "Penetration Testing Methodology",
            "framework_alignment": {
                "nist": "NIST SP 800-115 Technical Security Testing",
                "pentest_plus": "CompTIA PenTest+ Domains 1-6",
                "owasp": "OWASP Testing Guide v4.2",
                "ptes": "Penetration Testing Execution Standard"
            },
            "phases": [
                {
                    "phase": "Phase 1: Planning & Scoping (L1)",
                    "description": "Reconnaissance patterns identified, scope defined, rules of engagement established",
                    "duration": "Week 1-2",
                    "artifacts": ["recon_patterns.json", "scope_document.txt"]
                },
                {
                    "phase": "Phase 2: Discovery & Assessment (L2-L3)",
                    "description": "Information gathering, vulnerability scanning, risk assessment, CVSS scoring",
                    "duration": "Week 3-4",
                    "artifacts": ["findings_report.json", "vulnerability_summary.csv"]
                },
                {
                    "phase": "Phase 3: Attack & Exploitation (L4)",
                    "description": "Active exploitation, proof-of-concept demonstration, attack chain mapping",
                    "duration": "Week 4",
                    "artifacts": ["exploitation_report.json", "poc_demonstrations.md"]
                },
                {
                    "phase": "Phase 4: Post-Exploitation (L5)",
                    "description": "Persistence establishment, lateral movement, data discovery, impact quantification",
                    "duration": "Week 5",
                    "artifacts": ["post_exploitation_report.json", "business_impact_assessment.json"]
                },
                {
                    "phase": "Phase 5: Reporting & Remediation (L6)",
                    "description": "Report generation, remediation planning, compliance assessment, stakeholder communication",
                    "duration": "Week 6",
                    "artifacts": ["final_penetration_test_report.html", "remediation_roadmap.json"]
                }
            ]
        }
    
    def generate_detailed_findings(self) -> List[Dict]:
        """Generate detailed vulnerability findings with CVSS scoring."""
        logger.info("Generating detailed findings section")
        findings = [
            {
                "finding_id": "F-001",
                "title": "SQL Injection in Login Form",
                "severity": "CRITICAL",
                "cvss_score": "10.0",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "description": "The login form accepts user input without proper validation or parameterization, allowing SQL injection attacks.",
                "root_cause": "User-supplied input directly concatenated into SQL queries without input validation.",
                "proof_of_concept": "admin' OR '1'='1",
                "remediation": [
                    "Implement parameterized queries (prepared statements)",
                    "Use ORM frameworks (e.g., SQLAlchemy, Django ORM)",
                    "Apply input validation and sanitization",
                    "Implement Web Application Firewall (WAF) rules"
                ]
            },
            {
                "finding_id": "F-002",
                "title": "Weak Authentication (Default Credentials)",
                "severity": "CRITICAL",
                "cvss_score": "9.6",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "description": "Administrative interfaces accept default credentials (admin/password).",
                "root_cause": "Default credentials never changed during deployment.",
                "proof_of_concept": "Username: admin, Password: password (successful login)",
                "remediation": [
                    "Change all default credentials immediately",
                    "Implement strong password policy (minimum 12 characters, complexity)",
                    "Enable multi-factor authentication (MFA) on all admin accounts",
                    "Implement password manager for credential management"
                ]
            },
            {
                "finding_id": "F-003",
                "title": "Unprotected Configuration Backup File",
                "severity": "CRITICAL",
                "cvss_score": "9.0",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "description": "Sensitive configuration file publicly accessible via web server.",
                "root_cause": "Backup file stored in web root with insufficient access controls.",
                "proof_of_concept": "HTTP GET /backup/config.bak reveals database credentials",
                "remediation": [
                    "Move backup files outside web root",
                    "Implement strict file access controls (NTFS permissions)",
                    "Encrypt sensitive configuration data",
                    "Disable directory listing on web server",
                    "Implement WAF rules to block backup file access"
                ]
            }
        ]
        return findings
    
    def generate_attack_chains(self) -> List[Dict]:
        """Generate attack chain documentation - FIXED."""
        logger.info("Generating attack chains")
        return [
            {
                "chain_id": "AC-001",
                "name": "Default Credentials → Admin Panel → Database Backup Access",
                "steps": [
                    {
                        "step": 1,
                        "action": "Discovered admin panel on vulnerable.lab:8080/admin",
                        "time": "0 minutes",
                        "technique": "Information gathering (L1-L3)"
                    },
                    {
                        "step": 2,
                        "action": "Tested default credentials (admin/password)",
                        "time": "2 minutes",
                        "technique": "Weak authentication exploitation"
                    },
                    {
                        "step": 3,
                        "action": "Gained admin panel access with full system privileges",
                        "time": "3 minutes",
                        "technique": "Authentication bypass"
                    },
                    {
                        "step": 4,
                        "action": "Located unprotected backup file in /backup/config.bak",
                        "time": "5 minutes",
                        "technique": "Credential enumeration"
                    }
                ],
                "total_time_to_compromise": "5 minutes",
                "initial_access": "Default credentials",
                "escalation_vector": "Direct admin access",
                "final_impact": "Complete infrastructure compromise"
            },
            {
                "chain_id": "AC-002",
                "name": "SQL Injection → Database Access → Lateral Movement → Full Compromise",
                "steps": [
                    {
                        "step": 1,
                        "action": "Identified SQL injection vulnerability in login form",
                        "time": "0 minutes",
                        "technique": "Web application testing"
                    },
                    {
                        "step": 2,
                        "action": "Exploited SQL injection with: admin' OR '1'='1",
                        "time": "2 minutes",
                        "technique": "SQL injection exploitation"
                    },
                    {
                        "step": 3,
                        "action": "Extracted user credentials from user table (156,250 records)",
                        "time": "5 minutes",
                        "technique": "Database query manipulation"
                    },
                    {
                        "step": 4,
                        "action": "Used credentials to access database_server.lab (SMB/SSH)",
                        "time": "8 minutes",
                        "technique": "Lateral movement via SMB/SSH"
                    },
                    {
                        "step": 5,
                        "action": "Established persistence on all 3 systems (scheduled tasks, backdoor users)",
                        "time": "12 minutes",
                        "technique": "Persistence establishment (tasks, backdoors)"
                    }
                ],
                "total_time_to_compromise": "12 minutes",
                "initial_access": "SQL injection",
                "escalation_vector": "Credential theft → lateral movement",
                "final_impact": "Full network compromise with persistence"
            }
        ]
    
    def generate_remediation_roadmap(self) -> Dict:
        """Generate prioritized remediation roadmap."""
        logger.info("Generating remediation roadmap")
        return {
            "roadmap_title": "Penetration Test Remediation Roadmap",
            "total_findings": 10,
            "estimated_remediation_cost": 125000,
            "timeline_phases": [
                {
                    "phase": "IMMEDIATE (0-7 days)",
                    "priority": "CRITICAL",
                    "description": "Address CRITICAL vulnerabilities that allow complete compromise",
                    "actions": [
                        "Rotate all administrative credentials",
                        "Apply input validation and parameterized queries to SQL injection points",
                        "Move configuration files outside web root",
                        "Enable MFA on all admin accounts",
                        "Deploy temporary WAF rules to block exploitation attempts"
                    ],
                    "estimated_cost": "$35,000",
                    "estimated_effort": "40 hours"
                },
                {
                    "phase": "URGENT (7-30 days)",
                    "priority": "HIGH",
                    "description": "Address HIGH severity findings that enable lateral movement",
                    "actions": [
                        "Patch all identified vulnerabilities",
                        "Implement network segmentation (VLAN isolation)",
                        "Deploy IDS/IPS for anomaly detection",
                        "Implement centralized logging and SIEM",
                        "Conduct security awareness training"
                    ],
                    "estimated_cost": "$45,000",
                    "estimated_effort": "60 hours"
                },
                {
                    "phase": "PRIORITY (30-90 days)",
                    "priority": "MEDIUM",
                    "description": "Implement long-term security controls",
                    "actions": [
                        "Implement EDR (Endpoint Detection & Response)",
                        "Deploy DLP (Data Loss Prevention) solution",
                        "Implement threat intelligence integration",
                        "Conduct penetration test validation",
                        "Review and update security policies"
                    ],
                    "estimated_cost": "$30,000",
                    "estimated_effort": "50 hours"
                },
                {
                    "phase": "ENHANCEMENT (90+ days)",
                    "priority": "LOW",
                    "description": "Mature security posture improvements",
                    "actions": [
                        "Implement advanced threat protection",
                        "Deploy security orchestration (SOAR)",
                        "Establish managed detection and response (MDR)",
                        "Continuous vulnerability assessment",
                        "Red team exercises"
                    ],
                    "estimated_cost": "$15,000",
                    "estimated_effort": "30 hours"
                }
            ]
        }
    
    def generate_compliance_assessment(self) -> Dict:
        """Generate compliance impact assessment."""
        logger.info("Generating compliance assessment")
        return {
            "assessment_title": "Regulatory Compliance Impact",
            "regulations": [
                {
                    "regulation": "GDPR (General Data Protection Regulation)",
                    "applicability": "Organization processes data of EU residents",
                    "violation": "Unauthorized access to personal data (156,250 user records)",
                    "fines": "Up to 4% of annual revenue or €20M (whichever is higher)",
                    "compliance_status": "NON-COMPLIANT"
                },
                {
                    "regulation": "CCPA (California Consumer Privacy Act)",
                    "applicability": "Organization collects data of California residents",
                    "violation": "Unauthorized access to consumer personal information",
                    "fines": "$100-$750 per record per violation",
                    "compliance_status": "NON-COMPLIANT"
                },
                {
                    "regulation": "PCI DSS (Payment Card Industry Data Security Standard)",
                    "applicability": "Organization processes credit card payments",
                    "violation": "Exposure of payment card data (45,892 records)",
                    "fines": "$5,000-$100,000+ per month of non-compliance",
                    "compliance_status": "NON-COMPLIANT"
                },
                {
                    "regulation": "SOC 2 Type II (Service Organization Control)",
                    "applicability": "Organization provides cloud/SaaS services",
                    "violation": "Lack of security controls to protect customer data",
                    "fines": "Loss of customer trust and business partnerships",
                    "compliance_status": "NOT CERTIFIED"
                }
            ]
        }
    
    def generate_risk_dashboard(self) -> Dict:
        """Generate risk metrics and before/after comparison."""
        logger.info("Generating risk dashboard")
        return {
            "dashboard_title": "Executive Risk Dashboard",
            "report_date": datetime.now().isoformat(),
            "before_remediation": {
                "overall_risk_score": 95,
                "risk_rating": "CRITICAL",
                "critical_findings": 3,
                "high_findings": 5,
                "systems_at_risk": 4,
                "records_exposed": 493662,
                "estimated_annual_loss": 89529300,
                "likelihood_of_breach": "Very High (within 30 days)"
            },
            "after_remediation_projected": {
                "overall_risk_score": 35,
                "risk_rating": "MEDIUM",
                "critical_findings": 0,
                "high_findings": 0,
                "systems_at_risk": 1,
                "records_exposed": 0,
                "estimated_annual_loss": 500000,
                "likelihood_of_breach": "Low (12+ months)"
            },
            "risk_reduction_metrics": {
                "risk_score_reduction": "63%",
                "vulnerability_reduction": "50%",
                "financial_impact_reduction": "99.4%",
                "estimated_roi": "2.1x (within 18 months)"
            }
        }
    
    def generate_attestation(self) -> Dict:
        """Generate professional attestation of findings."""
        logger.info("Generating professional attestation")
        return {
            "attestation_title": "Attestation of Penetration Testing Findings",
            "report_id": f"PT-{datetime.now().strftime('%Y%m%d')}-001",
            "engagement_period": "2025-11-16 to 2025-11-30",
            "testing_methodology": "NIST SP 800-115 / CompTIA PenTest+",
            "attestation_statement": (
                "This Attestation of Findings certifies that a comprehensive penetration test was "
                "conducted on the organization's information systems during the specified engagement period. "
                "The findings documented in this report represent a true and accurate assessment of the "
                "security posture at the time of testing."
            ),
            "certified_by": {
                "tester_name": "Security Assessment Team",
                "title": "Penetration Testing Professional",
                "credentials": ["OSCP", "CEH", "GPEN"],
                "date": datetime.now().strftime("%Y-%m-%d")
            },
            "next_steps": [
                "Prioritize CRITICAL vulnerabilities for immediate remediation (0-7 days)",
                "Implement remediation roadmap according to defined timelines",
                "Conduct re-testing to validate remediation effectiveness",
                "Establish continuous vulnerability management program",
                "Schedule quarterly penetration testing for ongoing validation"
            ]
        }
    
    def export_html_report(self, filename: str = "final_penetration_test_report.html") -> None:
        """Export comprehensive HTML report."""
        logger.info(f"Generating HTML report: {filename}")
        
        executive_summary = self.generate_executive_summary()
        methodology = self.generate_methodology_section()
        findings = self.generate_detailed_findings()
        attack_chains = self.generate_attack_chains()
        remediation = self.generate_remediation_roadmap()
        compliance = self.generate_compliance_assessment()
        dashboard = self.generate_risk_dashboard()
        attestation = self.generate_attestation()
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {executive_summary.overall_risk_rating.value}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; border-radius: 8px; margin-bottom: 40px; text-align: center; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .risk-rating {{ display: inline-block; padding: 10px 20px; background-color: #dc3545; color: white; border-radius: 5px; font-weight: bold; margin-top: 10px; }}
        .section {{ background-color: white; padding: 30px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h2 {{ color: #667eea; margin-bottom: 20px; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .summary-card {{ background-color: #f8f9fa; padding: 20px; border-left: 4px solid #667eea; border-radius: 5px; }}
        .summary-card h3 {{ color: #667eea; margin-bottom: 10px; }}
        .summary-card .value {{ font-size: 1.8em; font-weight: bold; color: #333; }}
        .finding {{ background-color: #f8f9fa; padding: 20px; margin-bottom: 15px; border-left: 4px solid #dc3545; border-radius: 5px; }}
        .cvss-badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; margin-right: 10px; }}
        .cvss-critical {{ background-color: #dc3545; }}
        .cvss-high {{ background-color: #fd7e14; }}
        .remediation {{ background-color: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-top: 10px; border-radius: 5px; }}
        .attack-chain {{ background-color: #fff3cd; padding: 20px; margin-bottom: 15px; border-left: 4px solid #ffc107; border-radius: 5px; }}
        .timeline {{ position: relative; padding-left: 40px; }}
        .timeline-item {{ margin-bottom: 20px; position: relative; }}
        .timeline-item::before {{ content: ''; position: absolute; left: -25px; top: 5px; width: 12px; height: 12px; background-color: #667eea; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 0 2px #667eea; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #667eea; color: white; font-weight: bold; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .before-after {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }}
        .before {{ background-color: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 5px; }}
        .after {{ background-color: #d4edda; border: 2px solid #28a745; padding: 20px; border-radius: 5px; }}
        footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; border-top: 1px solid #ddd; margin-top: 40px; }}
        .page-break {{ page-break-after: always; }}
        @media print {{ body {{ background-color: white; }} .section {{ box-shadow: none; page-break-inside: avoid; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Penetration Test Report</h1>
            <p>Comprehensive Security Assessment</p>
            <div class="risk-rating">{executive_summary.overall_risk_rating.value} RISK</div>
        </header>

        <!-- EXECUTIVE SUMMARY -->
        <div class="section page-break">
            <h2>Executive Summary</h2>
            <p>{executive_summary.executive_statement}</p>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Overall Risk</h3>
                    <div class="value" style="color: #dc3545;">{executive_summary.overall_risk_rating.value}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerabilities Found</h3>
                    <div class="value">{executive_summary.total_vulnerabilities}</div>
                </div>
                <div class="summary-card">
                    <h3>Financial Impact</h3>
                    <div class="value">${executive_summary.financial_impact:,.0f}</div>
                </div>
                <div class="summary-card">
                    <h3>Systems Compromised</h3>
                    <div class="value">{executive_summary.systems_compromised}</div>
                </div>
            </div>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>CRITICAL Vulnerabilities</h3>
                    <div class="value" style="color: #dc3545;">{executive_summary.critical_vulnerabilities}</div>
                </div>
                <div class="summary-card">
                    <h3>HIGH Vulnerabilities</h3>
                    <div class="value" style="color: #fd7e14;">{executive_summary.high_vulnerabilities}</div>
                </div>
                <div class="summary-card">
                    <h3>Records Exposed</h3>
                    <div class="value">{executive_summary.records_exposed:,}</div>
                </div>
            </div>
        </div>

        <!-- METHODOLOGY -->
        <div class="section page-break">
            <h2>Methodology</h2>
            <h3>Framework Alignment</h3>
            <ul style="margin-left: 20px;">
                <li><strong>NIST:</strong> {methodology['framework_alignment']['nist']}</li>
                <li><strong>PenTest+:</strong> {methodology['framework_alignment']['pentest_plus']}</li>
            </ul>
            <h3 style="margin-top: 20px;">Testing Phases</h3>
            <table>
                <thead><tr><th>Phase</th><th>Duration</th><th>Objective</th></tr></thead>
                <tbody>
"""
        
        for phase in methodology['phases']:
            html_content += f"<tr><td>{phase['phase']}</td><td>{phase['duration']}</td><td>{phase['description']}</td></tr>"
        
        html_content += """
                </tbody>
            </table>
        </div>

        <!-- DETAILED FINDINGS -->
        <div class="section page-break">
            <h2>Detailed Findings</h2>
"""
        
        for finding in findings:
            severity_class = finding['severity'].lower()
            cvss_class = f"cvss-{severity_class}"
            html_content += f"""
            <div class="finding">
                <h3>{finding['finding_id']}: {finding['title']}</h3>
                <span class="cvss-badge {cvss_class}">{finding['cvss_score']}</span>
                <span style="color: #666;">Severity: {finding['severity']}</span>
                <p style="margin-top: 10px;"><strong>Description:</strong> {finding['description']}</p>
                <p><strong>Root Cause:</strong> {finding['root_cause']}</p>
                <p><strong>PoC:</strong> <code>{finding['proof_of_concept']}</code></p>
                <div class="remediation">
                    <strong>Remediation:</strong>
                    <ul style="margin-left: 20px; margin-top: 10px;">
"""
            for step in finding['remediation']:
                html_content += f"<li>{step}</li>"
            html_content += """
                    </ul>
                </div>
            </div>
"""
        
        html_content += """
        </div>

        <!-- ATTACK CHAINS -->
        <div class="section page-break">
            <h2>Attack Chains</h2>
"""
        
        for chain in attack_chains:
            html_content += f"""
            <div class="attack-chain">
                <h3>{chain['chain_id']}: {chain['name']}</h3>
                <p><strong>Time to Compromise:</strong> {chain['total_time_to_compromise']}</p>
                <div class="timeline">
"""
            for step in chain['steps']:
                html_content += f"""
                <div class="timeline-item">
                    <strong>Step {step['step']}:</strong> {step['action']}<br>
                    <small>Time: {step['time']} | Technique: {step['technique']}</small>
                </div>
"""
            html_content += """
                </div>
            </div>
"""
        
        html_content += """
        </div>

        <!-- REMEDIATION ROADMAP -->
        <div class="section page-break">
            <h2>Remediation Roadmap</h2>
"""
        
        for phase in remediation['timeline_phases']:
            html_content += f"""
            <div style="margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
                <h3>{phase['phase']} - {phase['priority']}</h3>
                <p>{phase['description']}</p>
                <p><strong>Cost:</strong> {phase['estimated_cost']} | <strong>Effort:</strong> {phase['estimated_effort']}</p>
                <strong>Actions:</strong>
                <ul style="margin-left: 20px; margin-top: 10px;">
"""
            for action in phase['actions']:
                html_content += f"<li>{action}</li>"
            html_content += """
                </ul>
            </div>
"""
        
        html_content += """
        </div>

        <!-- COMPLIANCE -->
        <div class="section page-break">
            <h2>Compliance Impact Assessment</h2>
"""
        
        for reg in compliance['regulations']:
            html_content += f"""
            <div style="margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; border-left: 4px solid #dc3545;">
                <h3>{reg['regulation']}</h3>
                <p><strong>Violation:</strong> {reg['violation']}</p>
                <p><strong>Status:</strong> <span style="color: #dc3545; font-weight: bold;">{reg['compliance_status']}</span></p>
                <p><strong>Fines:</strong> {reg['fines']}</p>
            </div>
"""
        
        html_content += """
        </div>

        <!-- RISK DASHBOARD -->
        <div class="section page-break">
            <h2>Risk Dashboard</h2>
            <div class="before-after">
                <div class="before">
                    <h3>Before Remediation</h3>
"""
        
        html_content += f"""
                    <p><strong>Risk Score:</strong> <span style="font-size: 1.5em; color: #dc3545;">{dashboard['before_remediation']['overall_risk_score']}</span>/100</p>
                    <p><strong>Rating:</strong> {dashboard['before_remediation']['risk_rating']}</p>
                    <p><strong>Financial Impact:</strong> ${dashboard['before_remediation']['estimated_annual_loss']:,}</p>
                </div>
                <div class="after">
                    <h3>After Remediation (Projected)</h3>
                    <p><strong>Risk Score:</strong> <span style="font-size: 1.5em; color: #28a745;">{dashboard['after_remediation_projected']['overall_risk_score']}</span>/100</p>
                    <p><strong>Rating:</strong> {dashboard['after_remediation_projected']['risk_rating']}</p>
                    <p><strong>Financial Impact:</strong> ${dashboard['after_remediation_projected']['estimated_annual_loss']:,}</p>
                </div>
            </div>
            <h3 style="margin-top: 20px;">Risk Reduction</h3>
            <p><strong>Score Reduction:</strong> <span style="color: #28a745; font-weight: bold;">{dashboard['risk_reduction_metrics']['risk_score_reduction']}</span></p>
            <p><strong>Financial Impact Reduction:</strong> <span style="color: #28a745; font-weight: bold;">{dashboard['risk_reduction_metrics']['financial_impact_reduction']}</span></p>
            <p><strong>Estimated ROI:</strong> <span style="color: #28a745; font-weight: bold;">{dashboard['risk_reduction_metrics']['estimated_roi']}</span></p>
        </div>

        <!-- ATTESTATION -->
        <div class="section page-break">
            <h2>Professional Attestation</h2>
            <p><strong>Report ID:</strong> {attestation['report_id']}</p>
            <p><strong>Period:</strong> {attestation['engagement_period']}</p>
            <p><strong>Methodology:</strong> {attestation['testing_methodology']}</p>
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-top: 20px;">
                <p>{attestation['attestation_statement']}</p>
            </div>
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                <p><strong>Certified by:</strong> {attestation['certified_by']['tester_name']}</p>
                <p><strong>Title:</strong> {attestation['certified_by']['title']}</p>
                <p><strong>Credentials:</strong> {', '.join(attestation['certified_by']['credentials'])}</p>
                <p><strong>Date:</strong> {attestation['certified_by']['date']}</p>
            </div>
        </div>

        <footer>
            <p>This report contains confidential and proprietary information.</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"✓ HTML report exported to {filename}")
    
    def export_json_report(self, filename: str = "penetration_test_report.json") -> None:
        """Export comprehensive report data as JSON."""
        logger.info(f"Generating JSON report: {filename}")
        
        report_data = {
            "report_generated": datetime.now().isoformat(),
            "executive_summary": asdict(self.generate_executive_summary()),
            "methodology": self.generate_methodology_section(),
            "detailed_findings": self.generate_detailed_findings(),
            "attack_chains": self.generate_attack_chains(),
            "remediation_roadmap": self.generate_remediation_roadmap(),
            "compliance_assessment": self.generate_compliance_assessment(),
            "risk_dashboard": self.generate_risk_dashboard(),
            "attestation": self.generate_attestation()
        }
        
        def json_serializer(obj):
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=json_serializer)
        
        logger.info(f"✓ JSON report exported to {filename}")

def main():
    """Generate comprehensive penetration test report."""
    
    logger.info("=" * 80)
    logger.info("LabLeakFinder - L6 Final Penetration Test Report Generator")
    logger.info("Domain: Reporting & Communication")
    logger.info("=" * 80)
    
    generator = PenetrationTestReportGenerator()
    
    logger.info("\n" + "=" * 80)
    logger.info("GENERATING FINAL REPORT ARTIFACTS")
    logger.info("=" * 80)
    
    logger.info("\n[1/2] Generating HTML Report...")
    generator.export_html_report("final_penetration_test_report.html")
    
    logger.info("\n[2/2] Generating JSON Report...")
    generator.export_json_report("penetration_test_report.json")
    
    logger.info("\n" + "=" * 80)
    logger.info("L6 REPORT GENERATION COMPLETE")
    logger.info("=" * 80)
    logger.info("\nReport Deliverables:")
    logger.info("  ✓ final_penetration_test_report.html - Professional web report")
    logger.info("  ✓ penetration_test_report.json - Data export")
    logger.info("\nNext Steps:")
    logger.info("  1. Open report in browser: final_penetration_test_report.html")
    logger.info("  2. Review findings and recommendation")
    logger.info("  3. Begin remediation per roadmap")
    logger.info("  4. Schedule re-testing after fixes")
    logger.info("\n" + "=" * 80)

if __name__ == "__main__":
    main()

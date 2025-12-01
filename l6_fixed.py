"""
LabLeakFinder L6: Final Penetration Test Report Generator
Domain: Reporting & Communication (PenTest+ Domain 6)
"""

import json
import logging
import sys
from typing import Dict, List
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('labfinder_l6_detailed.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class RiskRating(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

@dataclass
class ExecutiveSummary:
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
    def __init__(self):
        self.business_impact = {
            "total_financial_impact": 89529300,
            "data_breach_notification": 74049300,
            "operational_downtime": 480000,
            "regulatory_fines": 5000000,
            "reputational_damage": 10000000
        }
        logger.info("PenetrationTestReportGenerator initialized")
    
    def generate_executive_summary(self) -> ExecutiveSummary:
        logger.info("Generating executive summary")
        return ExecutiveSummary(
            overall_risk_rating=RiskRating.CRITICAL,
            total_vulnerabilities=10,
            critical_vulnerabilities=3,
            high_vulnerabilities=5,
            financial_impact=89529300,
            systems_compromised=3,
            records_exposed=493662,
            recommendation="Immediate action required to remediate CRITICAL vulnerabilities within 48 hours.",
            executive_statement="The penetration test identified CRITICAL security vulnerabilities that allow complete compromise of the organization's infrastructure."
        )
    
    def generate_detailed_findings(self) -> List[Dict]:
        logger.info("Generating detailed findings section")
        return [
            {
                "finding_id": "F-001",
                "title": "SQL Injection in Login Form",
                "severity": "CRITICAL",
                "cvss_score": "10.0",
                "description": "The login form accepts user input without proper validation.",
                "root_cause": "User-supplied input directly concatenated into SQL queries.",
                "proof_of_concept": "admin' OR '1'='1",
                "remediation": ["Implement parameterized queries", "Use ORM frameworks"]
            },
            {
                "finding_id": "F-002",
                "title": "Weak Authentication",
                "severity": "CRITICAL",
                "cvss_score": "9.6",
                "description": "Administrative interfaces accept default credentials.",
                "root_cause": "Default credentials never changed.",
                "proof_of_concept": "admin/password",
                "remediation": ["Change all default credentials", "Enable MFA"]
            },
            {
                "finding_id": "F-003",
                "title": "Unprotected Configuration Backup",
                "severity": "CRITICAL",
                "cvss_score": "9.0",
                "description": "Sensitive config file publicly accessible.",
                "root_cause": "Backup file stored in web root.",
                "proof_of_concept": "HTTP GET /backup/config.bak",
                "remediation": ["Move backup files outside web root", "Encrypt sensitive data"]
            }
        ]
    
    def generate_attack_chains(self) -> List[Dict]:
        logger.info("Generating attack chains")
        return [
            {
                "chain_id": "AC-001",
                "name": "Default Credentials Attack Chain",
                "steps": [
                    {"step": 1, "action": "Discovered admin panel", "time": "0 minutes", "technique": "Information gathering"},
                    {"step": 2, "action": "Tested default credentials", "time": "2 minutes", "technique": "Weak authentication"},
                    {"step": 3, "action": "Gained admin access", "time": "3 minutes", "technique": "Authentication bypass"},
                    {"step": 4, "action": "Found backup file", "time": "5 minutes", "technique": "Credential enumeration"}
                ],
                "total_time_to_compromise": "5 minutes"
            },
            {
                "chain_id": "AC-002",
                "name": "SQL Injection Attack Chain",
                "steps": [
                    {"step": 1, "action": "Identified SQL injection", "time": "0 minutes", "technique": "Web application testing"},
                    {"step": 2, "action": "Exploited SQL injection", "time": "2 minutes", "technique": "SQL injection exploitation"},
                    {"step": 3, "action": "Extracted credentials", "time": "5 minutes", "technique": "Database query manipulation"},
                    {"step": 4, "action": "Accessed database server", "time": "8 minutes", "technique": "Lateral movement"},
                    {"step": 5, "action": "Established persistence", "time": "12 minutes", "technique": "Persistence establishment"}
                ],
                "total_time_to_compromise": "12 minutes"
            }
        ]
    
    def generate_remediation_roadmap(self) -> Dict:
        logger.info("Generating remediation roadmap")
        return {
            "total_findings": 10,
            "estimated_remediation_cost": 125000,
            "timeline_phases": [
                {
                    "phase": "IMMEDIATE (0-7 days)",
                    "priority": "CRITICAL",
                    "description": "Address CRITICAL vulnerabilities",
                    "actions": ["Rotate admin credentials", "Apply input validation", "Move config files", "Enable MFA"],
                    "estimated_cost": "$35,000",
                    "estimated_effort": "40 hours"
                },
                {
                    "phase": "URGENT (7-30 days)",
                    "priority": "HIGH",
                    "description": "Address HIGH severity findings",
                    "actions": ["Patch vulnerabilities", "Network segmentation", "Deploy IDS/IPS"],
                    "estimated_cost": "$45,000",
                    "estimated_effort": "60 hours"
                }
            ]
        }
    
    def generate_risk_dashboard(self) -> Dict:
        logger.info("Generating risk dashboard")
        return {
            "before_remediation": {
                "overall_risk_score": 95,
                "risk_rating": "CRITICAL",
                "estimated_annual_loss": 89529300
            },
            "after_remediation_projected": {
                "overall_risk_score": 35,
                "risk_rating": "MEDIUM",
                "estimated_annual_loss": 500000
            },
            "risk_reduction_metrics": {
                "risk_score_reduction": "63%",
                "financial_impact_reduction": "99.4%"
            }
        }
    
    def export_html_report(self, filename: str = "final_penetration_test_report.html") -> None:
        logger.info(f"Generating HTML report: {filename}")
        
        exec_summary = self.generate_executive_summary()
        findings = self.generate_detailed_findings()
        attack_chains = self.generate_attack_chains()
        remediation = self.generate_remediation_roadmap()
        dashboard = self.generate_risk_dashboard()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {exec_summary.overall_risk_rating.value}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; border-radius: 8px; margin-bottom: 40px; text-align: center; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .risk-rating {{ display: inline-block; padding: 10px 20px; background: #dc3545; color: white; border-radius: 5px; font-weight: bold; }}
        .section {{ background: white; padding: 30px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h2 {{ color: #667eea; margin-bottom: 20px; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-left: 4px solid #667eea; border-radius: 5px; }}
        .summary-card .value {{ font-size: 1.8em; font-weight: bold; color: #333; }}
        .finding {{ background: #f8f9fa; padding: 20px; margin-bottom: 15px; border-left: 4px solid #dc3545; border-radius: 5px; }}
        .cvss-badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; margin-right: 10px; }}
        .cvss-critical {{ background: #dc3545; }}
        .remediation {{ background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-top: 10px; border-radius: 5px; }}
        .attack-chain {{ background: #fff3cd; padding: 20px; margin-bottom: 15px; border-left: 4px solid #ffc107; border-radius: 5px; }}
        .timeline {{ position: relative; padding-left: 40px; }}
        .timeline-item {{ margin-bottom: 20px; position: relative; }}
        .timeline-item::before {{ content: ''; position: absolute; left: -25px; top: 5px; width: 12px; height: 12px; background: #667eea; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 0 2px #667eea; }}
        footer {{ text-align: center; padding: 20px; color: #666; border-top: 1px solid #ddd; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Penetration Test Report</h1>
            <p>Comprehensive Security Assessment</p>
            <div class="risk-rating">{exec_summary.overall_risk_rating.value} RISK</div>
        </header>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>{exec_summary.executive_statement}</p>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Risk Level</h3>
                    <div class="value" style="color: #dc3545;">{exec_summary.overall_risk_rating.value}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerabilities</h3>
                    <div class="value">{exec_summary.total_vulnerabilities}</div>
                </div>
                <div class="summary-card">
                    <h3>Financial Impact</h3>
                    <div class="value">${exec_summary.financial_impact:,.0f}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>
"""
        
        for finding in findings:
            html += f"""
            <div class="finding">
                <h3>{finding['finding_id']}: {finding['title']}</h3>
                <span class="cvss-badge cvss-critical">{finding['cvss_score']}</span>
                <p style="margin-top: 10px;"><strong>Description:</strong> {finding['description']}</p>
                <div class="remediation">
                    <strong>Remediation:</strong>
                    <ul style="margin-left: 20px;">
                        <li>{finding['remediation'][0]}</li>
                        <li>{finding['remediation'][1]}</li>
                    </ul>
                </div>
            </div>
"""
        
        html += """
        </div>

        <div class="section">
            <h2>Attack Chains</h2>
"""
        
        for chain in attack_chains:
            html += f"""
            <div class="attack-chain">
                <h3>{chain['chain_id']}: {chain['name']}</h3>
                <p><strong>Time to Compromise:</strong> {chain['total_time_to_compromise']}</p>
                <div class="timeline">
"""
            for step in chain['steps']:
                html += f"""
                <div class="timeline-item">
                    <strong>Step {step['step']}:</strong> {step['action']}<br>
                    <small>Time: {step['time']} | Technique: {step['technique']}</small>
                </div>
"""
            html += """
                </div>
            </div>
"""
        
        html += f"""
        </div>

        <div class="section">
            <h2>Risk Dashboard</h2>
            <p><strong>Before Remediation:</strong> {dashboard['before_remediation']['overall_risk_score']}/100 ({dashboard['before_remediation']['risk_rating']})</p>
            <p><strong>After Remediation:</strong> {dashboard['after_remediation_projected']['overall_risk_score']}/100 ({dashboard['after_remediation_projected']['risk_rating']})</p>
            <p><strong>Risk Reduction:</strong> {dashboard['risk_reduction_metrics']['risk_score_reduction']}</p>
        </div>

        <footer>
            <p>Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"✓ HTML report exported to {filename}")
    
    def export_json_report(self, filename: str = "penetration_test_report.json") -> None:
        logger.info(f"Generating JSON report: {filename}")
        
        report_data = {
            "report_generated": datetime.now().isoformat(),
            "executive_summary": asdict(self.generate_executive_summary()),
            "detailed_findings": self.generate_detailed_findings(),
            "attack_chains": self.generate_attack_chains(),
            "remediation_roadmap": self.generate_remediation_roadmap(),
            "risk_dashboard": self.generate_risk_dashboard(),
        }
        
        def json_serializer(obj):
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=json_serializer)
        
        logger.info(f"✓ JSON report exported to {filename}")

def main():
    logger.info("=" * 80)
    logger.info("LabLeakFinder - L6 Final Penetration Test Report Generator")
    logger.info("Domain: Reporting & Communication")
    logger.info("=" * 80)
    
    generator = PenetrationTestReportGenerator()
    
    logger.info("\nGenerating final report artifacts...")
    generator.export_html_report("final_penetration_test_report.html")
    generator.export_json_report("penetration_test_report.json")
    
    logger.info("\n" + "=" * 80)
    logger.info("L6 REPORT GENERATION COMPLETE!")
    logger.info("=" * 80)
    logger.info("\nDeliverables:")
    logger.info("  ✓ final_penetration_test_report.html")
    logger.info("  ✓ penetration_test_report.json")
    logger.info("=" * 80)

if __name__ == "__main__":
    main()

"""
LabLeakFinder L3: Result Analyzer
Domain: Vulnerability Analysis & Reporting (PenTest+ Domain 2 → 3 transition)

Purpose:
    Execute formatted queries, analyze results for security exposures.
    Match against known vulnerability signatures.
    Generate comprehensive findings reports with CVSS scoring.

Key Functions:
    - Query execution simulation (real search engine integration optional)
    - Result parsing and normalization
    - Vulnerability signature matching (CVE/NVD database)
    - CVSS score calculation
    - Finding aggregation and prioritization
    - Report generation (executive summary + technical details)
    - SIEM-like data correlation

Integration:
    INPUT: L2 Formatted Queries (formatted_queries.json)
    OUTPUT: 
        - findings_report.json (structured findings)
        - findings_report.html (executive report)
        - vulnerability_summary.csv (prioritized list)
    
PenTest+ Alignment:
    - Domain 2: Information Gathering (query execution)
    - Domain 3: Vulnerability Identification (signature matching)
    - Domain 4: Reporting & Communication (findings + remediation)
"""

import json
import logging
import sys
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from collections import defaultdict
import csv

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('labfinder_l3_detailed.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class FindingStatus(Enum):
    """Status of a security finding."""
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"

@dataclass
class CVSSScore:
    """CVSS v3.1 Score representation."""
    vector: str  # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    base_score: float  # 0.0-10.0
    severity_rating: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    @classmethod
    def calculate(cls, exploitability: float, impact: float) -> 'CVSSScore':
        """Simple CVSS v3.1 approximation."""
        base_score = min(10.0, (exploitability * 0.8) + (impact * 0.2))
        
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        elif base_score >= 0.1:
            severity = "LOW"
        else:
            severity = "INFO"
        
        vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{int(impact*10)}/I:{int(impact*8)}/A:{int(impact*6)}"
        
        return cls(vector=vector, base_score=base_score, severity_rating=severity)

@dataclass
class SecurityFinding:
    """A security finding from query analysis."""
    finding_id: str
    query_id: int
    target_domain: str
    exposure_type: str
    vulnerability_title: str
    description: str
    cve_references: List[str]
    cvss_score: CVSSScore
    status: FindingStatus
    evidence: str
    remediation: str
    timestamp: str

class VulnerabilitySignatureDatabase:
    """Database of known vulnerabilities and signatures."""
    
    def __init__(self):
        self.signatures = self._initialize_signatures()
        logger.info(f"Loaded {len(self.signatures)} vulnerability signatures")
    
    def _initialize_signatures(self) -> Dict:
        """Initialize known vulnerability signatures."""
        return {
            "directory_listing": {
                "title": "Directory Listing Exposed",
                "cves": ["CVE-2019-1234", "CWE-548"],
                "description": "Web server directory indexing is enabled, allowing attackers to browse file structure.",
                "exploitability": 8.0,
                "impact": 6.0,
                "remediation": "Disable directory listing in web server configuration (Options -Indexes in Apache, remove default.aspx in IIS).",
                "keywords": ["Index of", "Directory listing", "Parent Directory"]
            },
            "backup_file": {
                "title": "Backup Files Accessible",
                "cves": ["CVE-2020-5678", "CWE-426"],
                "description": "Backup files (.bak, .backup, .old) are accessible via web, exposing sensitive code and configurations.",
                "exploitability": 9.0,
                "impact": 9.0,
                "remediation": "Remove backup files from web root. Use .gitignore and deployment scripts to prevent accidental inclusion.",
                "keywords": [".bak", ".backup", ".old", ".tmp", "~"]
            },
            "config_file": {
                "title": "Configuration Files Exposed",
                "cves": ["CVE-2021-9999", "CWE-522"],
                "description": "Configuration files containing credentials, database info, and API keys are accessible.",
                "exploitability": 10.0,
                "impact": 10.0,
                "remediation": "Move config files outside web root. Use environment variables for sensitive data. Implement .htaccess restrictions.",
                "keywords": [".conf", ".config", ".ini", ".env", "web.config"]
            },
            "debug_info": {
                "title": "Debug Information Exposed",
                "cves": ["CVE-2020-1111", "CWE-215"],
                "description": "Debug information, stack traces, and error messages reveal application internals and versions.",
                "exploitability": 7.0,
                "impact": 5.0,
                "remediation": "Disable debug mode in production. Implement custom error pages. Configure proper logging.",
                "keywords": ["stack trace", "debug", "verbose error", "exception", "traceback"]
            },
            "admin_panel": {
                "title": "Administrative Interface Exposed",
                "cves": ["CVE-2021-2222", "CWE-269"],
                "description": "Admin panels accessible without proper authentication or with default credentials.",
                "exploitability": 9.5,
                "impact": 10.0,
                "remediation": "Require strong authentication. IP whitelist admin interfaces. Disable default accounts.",
                "keywords": ["/admin", "/login", "/management", "administrative", "control panel"]
            },
            "version_disclosure": {
                "title": "Application Version Disclosed",
                "cves": ["CVE-2019-0001", "CWE-200"],
                "description": "Application version numbers in banners, headers, or error messages allow targeted exploitation.",
                "exploitability": 3.0,
                "impact": 5.0,
                "remediation": "Remove version strings from HTTP headers. Customize server banners.",
                "keywords": ["version", "Apache", "nginx", "IIS", "Release"]
            }
        }
    
    def get_signature(self, exposure_type: str) -> Optional[Dict]:
        """Retrieve signature for exposure type."""
        return self.signatures.get(exposure_type)

class ResultAnalyzer:
    """
    Analyzes formatted queries for security exposures.
    
    Implements:
    - Query result parsing
    - Signature matching against known vulnerabilities
    - CVSS scoring
    - Finding aggregation
    - Report generation
    """
    
    def __init__(self, formatted_queries_file: str = "formatted_queries.json"):
        self.db = VulnerabilitySignatureDatabase()
        self.formatted_queries = self._load_queries(formatted_queries_file)
        self.findings = []
        self.finding_counter = 0
        
        logger.info(f"ResultAnalyzer initialized with {len(self.formatted_queries)} queries")
    
    def _load_queries(self, filename: str) -> List[Dict]:
        """Load formatted queries from L2."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('queries', [])
        except FileNotFoundError:
            logger.error(f"Formatted queries file not found: {filename}")
            return []
    
    def _simulate_query_execution(self, query: Dict) -> Tuple[bool, str]:
        """
        Simulate query execution and result detection.
        
        In production, this would execute real search queries.
        For lab purposes, we simulate based on exposure type.
        """
        exposure_type = query.get('exposure_type')
        
        # Simulated result evidence based on exposure type
        evidence_map = {
            "directory_listing": "Index of /uploads\n[DIR] configs/\n[DIR] backups/\n[-] backup_2024.sql",
            "backup_file": "[22K] application.conf.bak\n[45K] database.config.old\n[12K] secrets.env~",
            "config_file": "[33K] web.config containing database credentials\n[18K] settings.ini with API keys",
            "debug_info": "Fatal error in /app/upload.php on line 45\nStack trace: [...]\nMySQL Error: Table 'users' not found",
            "admin_panel": "Admin login panel at /admin/login.php\nDefault credentials: admin/admin detected as valid",
            "version_disclosure": "Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3\nContent-Management-System: WordPress 5.8.1"
        }
        
        # Return True (found) for all types in simulation
        evidence = evidence_map.get(exposure_type, "Exposure detected")
        return True, evidence
    
    def analyze_queries(self) -> List[SecurityFinding]:
        """Analyze all formatted queries for security exposures."""
        logger.info(f"Analyzing {len(self.formatted_queries)} formatted queries")
        
        for query in self.formatted_queries:
            # Execute query (simulated)
            found, evidence = self._simulate_query_execution(query)
            
            if not found:
                continue
            
            # Match against signature database
            exposure_type = query.get('exposure_type')
            signature = self.db.get_signature(exposure_type)
            
            if not signature:
                logger.warning(f"No signature found for {exposure_type}")
                continue
            
            # Calculate CVSS score
            cvss = CVSSScore.calculate(
                signature['exploitability'],
                signature['impact']
            )
            
            # Create finding
            self.finding_counter += 1
            finding = SecurityFinding(
                finding_id=f"FIND-{self.finding_counter:04d}",
                query_id=query.get('query_id'),
                target_domain=query.get('target_domain'),
                exposure_type=exposure_type,
                vulnerability_title=signature['title'],
                description=signature['description'],
                cve_references=signature['cves'],
                cvss_score=cvss,
                status=FindingStatus.CONFIRMED,
                evidence=evidence,
                remediation=signature['remediation'],
                timestamp=datetime.utcnow().isoformat()
            )
            
            self.findings.append(finding)
            logger.info(f"[FINDING] {finding.finding_id}: {signature['title']} ({cvss.severity_rating})")
        
        logger.info(f"Analysis complete. {len(self.findings)} findings identified.")
        return self.findings
    
    def get_summary_statistics(self) -> Dict:
        """Generate summary statistics of findings."""
        by_severity = defaultdict(int)
        by_exposure = defaultdict(int)
        by_domain = defaultdict(int)
        
        for finding in self.findings:
            by_severity[finding.cvss_score.severity_rating] += 1
            by_exposure[finding.exposure_type] += 1
            by_domain[finding.target_domain] += 1
        
        return {
            "total_findings": len(self.findings),
            "by_severity": dict(by_severity),
            "by_exposure_type": dict(by_exposure),
            "by_target_domain": dict(by_domain),
            "critical_count": by_severity.get("CRITICAL", 0),
            "high_count": by_severity.get("HIGH", 0),
            "medium_count": by_severity.get("MEDIUM", 0)
        }
    
    def export_findings_json(self, filename: str = "findings_report.json") -> None:
        """Export findings to JSON."""
        export_data = {
            "report_generated": datetime.utcnow().isoformat(),
            "total_findings": len(self.findings),
            "summary": self.get_summary_statistics(),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "query_id": f.query_id,
                    "target_domain": f.target_domain,
                    "exposure_type": f.exposure_type,
                    "vulnerability_title": f.vulnerability_title,
                    "description": f.description,
                    "cve_references": f.cve_references,
                    "cvss_score": f.cvss_score.base_score,
                    "cvss_severity": f.cvss_score.severity_rating,
                    "status": f.status.value,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "timestamp": f.timestamp
                }
                for f in sorted(self.findings, key=lambda x: x.cvss_score.base_score, reverse=True)
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported findings to {filename}")
    
    def export_findings_csv(self, filename: str = "vulnerability_summary.csv") -> None:
        """Export findings to CSV for prioritization."""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Finding ID', 'Domain', 'Exposure Type', 'Vulnerability', 'CVSS Score',
                'Severity', 'CVE References', 'Evidence', 'Remediation'
            ])
            
            for finding in sorted(self.findings, key=lambda x: x.cvss_score.base_score, reverse=True):
                writer.writerow([
                    finding.finding_id,
                    finding.target_domain,
                    finding.exposure_type,
                    finding.vulnerability_title,
                    f"{finding.cvss_score.base_score:.1f}",
                    finding.cvss_score.severity_rating,
                    "; ".join(finding.cve_references),
                    finding.evidence[:100],
                    finding.remediation[:100]
                ])
        
        logger.info(f"Exported CSV summary to {filename}")
    
    def export_findings_html(self, filename: str = "findings_report.html") -> None:
        """Export findings as professional HTML report."""
        summary = self.get_summary_statistics()
        findings_sorted = sorted(self.findings, key=lambda x: x.cvss_score.base_score, reverse=True)
        
        severity_colors = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#388e3c",
            "INFO": "#0288d1"
        }
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LabLeakFinder - Vulnerability Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 40px auto; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 40px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .section {{ padding: 30px; border-bottom: 1px solid #e0e0e0; }}
        .section h2 {{ color: #1e3c72; margin-bottom: 20px; font-size: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }}
        .stat-box {{ background: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 4px solid #2a5298; }}
        .stat-number {{ font-size: 32px; font-weight: bold; color: #1e3c72; }}
        .stat-label {{ font-size: 14px; color: #666; margin-top: 5px; }}
        .finding {{ background: #fafafa; padding: 20px; margin-bottom: 15px; border-radius: 6px; border-left: 4px solid; }}
        .finding.critical {{ border-left-color: {severity_colors['CRITICAL']}; }}
        .finding.high {{ border-left-color: {severity_colors['HIGH']}; }}
        .finding.medium {{ border-left-color: {severity_colors['MEDIUM']}; }}
        .finding.low {{ border-left-color: {severity_colors['LOW']}; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px; }}
        .finding-title {{ font-weight: bold; font-size: 16px; color: #1e3c72; }}
        .finding-id {{ font-size: 12px; color: #999; }}
        .severity-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }}
        .severity-critical {{ background: {severity_colors['CRITICAL']}; }}
        .severity-high {{ background: {severity_colors['HIGH']}; }}
        .severity-medium {{ background: {severity_colors['MEDIUM']}; }}
        .severity-low {{ background: {severity_colors['LOW']}; }}
        .finding-meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 10px 0; font-size: 13px; }}
        .finding-detail {{ margin: 10px 0; }}
        .detail-label {{ color: #666; font-weight: 500; }}
        .finding-evidence {{ background: white; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; max-height: 150px; overflow-y: auto; border: 1px solid #e0e0e0; }}
        .finding-remediation {{ background: #e8f5e9; padding: 12px; border-radius: 4px; border-left: 3px solid #388e3c; margin: 10px 0; }}
        .footer {{ background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #999; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 LabLeakFinder - Vulnerability Assessment Report</h1>
            <p>Comprehensive Security Findings & Remediation Guide</p>
            <p style="font-size: 12px; margin-top: 10px;">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p style="margin-bottom: 20px;">
                This report details the security assessment findings from the LabLeakFinder reconnaissance campaign.
                A total of <strong>{summary['total_findings']} vulnerabilities</strong> were identified across the target environment.
            </p>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{summary.get('critical_count', 0)}</div>
                    <div class="stat-label">CRITICAL</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{summary.get('high_count', 0)}</div>
                    <div class="stat-label">HIGH</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{summary.get('medium_count', 0)}</div>
                    <div class="stat-label">MEDIUM</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{summary['total_findings']}</div>
                    <div class="stat-label">TOTAL</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
            {"".join([f'''
            <div class="finding {finding.cvss_score.severity_rating.lower()}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{finding.vulnerability_title}</div>
                        <div class="finding-id">{finding.finding_id}</div>
                    </div>
                    <span class="severity-badge severity-{finding.cvss_score.severity_rating.lower()}">{finding.cvss_score.severity_rating}</span>
                </div>
                <div class="finding-meta">
                    <div class="finding-detail">
                        <div class="detail-label">CVSS Score:</div>
                        <div>{finding.cvss_score.base_score:.1f}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="detail-label">Target Domain:</div>
                        <div>{finding.target_domain}</div>
                    </div>
                </div>
                <div class="finding-detail">
                    <div class="detail-label">Description:</div>
                    <div>{finding.description}</div>
                </div>
                <div class="finding-detail">
                    <div class="detail-label">Evidence Detected:</div>
                    <div class="finding-evidence">{finding.evidence}</div>
                </div>
                <div class="finding-remediation">
                    <strong>✓ Remediation:</strong> {finding.remediation}
                </div>
                <div class="finding-detail" style="font-size: 12px; color: #999;">
                    References: {", ".join(finding.cve_references)}
                </div>
            </div>
            ''' for finding in findings_sorted])}
        </div>
        
        <div class="footer">
            <p>LabLeakFinder - Penetration Testing & Vulnerability Assessment Tool</p>
            <p>For authorized security testing only. Use responsibly and ethically.</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Exported HTML report to {filename}")

def main():
    """Demonstrate L3 Result Analyzer functionality."""
    
    logger.info("=" * 80)
    logger.info("LabLeakFinder - L3 Result Analyzer")
    logger.info("Domain: Vulnerability Analysis & Reporting")
    logger.info("=" * 80)
    
    analyzer = ResultAnalyzer(formatted_queries_file="formatted_queries.json")
    
    logger.info("\n" + "=" * 80)
    logger.info("PHASE 1: QUERY EXECUTION & ANALYSIS")
    logger.info("=" * 80)
    
    findings = analyzer.analyze_queries()
    
    logger.info("\n" + "=" * 80)
    logger.info("PHASE 2: FINDINGS SUMMARY")
    logger.info("=" * 80)
    
    summary = analyzer.get_summary_statistics()
    logger.info(f"\nTotal Findings: {summary['total_findings']}")
    logger.info(f"By Severity:")
    for severity, count in sorted(summary['by_severity'].items()):
        logger.info(f"  {severity}: {count}")
    logger.info(f"\nBy Exposure Type:")
    for exposure, count in sorted(summary['by_exposure_type'].items()):
        logger.info(f"  {exposure}: {count}")
    
    logger.info("\n" + "=" * 80)
    logger.info("PHASE 3: TOP CRITICAL FINDINGS")
    logger.info("=" * 80)
    
    critical_findings = [f for f in findings if f.cvss_score.severity_rating == "CRITICAL"]
    for finding in critical_findings[:5]:
        logger.info(f"\n[{finding.finding_id}] {finding.vulnerability_title}")
        logger.info(f"  CVSS: {finding.cvss_score.base_score:.1f}")
        logger.info(f"  Domain: {finding.target_domain}")
        logger.info(f"  Remediation: {finding.remediation[:60]}...")
    
    logger.info("\n" + "=" * 80)
    logger.info("PHASE 4: REPORT GENERATION")
    logger.info("=" * 80)
    
    analyzer.export_findings_json("findings_report.json")
    analyzer.export_findings_csv("vulnerability_summary.csv")
    analyzer.export_findings_html("findings_report.html")
    
    logger.info("\n✓ findings_report.json - Structured findings data")
    logger.info("✓ vulnerability_summary.csv - Prioritized vulnerability list")
    logger.info("✓ findings_report.html - Executive summary report")
    
    logger.info("\n" + "=" * 80)
    logger.info("L3 Result Analyzer Complete - Ready for Exploitation Phase")
    logger.info("=" * 80)

if __name__ == "__main__":
    main()

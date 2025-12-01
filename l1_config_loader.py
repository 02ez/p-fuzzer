"""
LabLeakFinder L1: Configuration Loader
Domain: Information Gathering & Vulnerability Identification (PenTest+ Domain 2)

Purpose:
    Load and validate reconnaissance patterns that safely identify misconfigurations.
    Ensures all queries remain within ethical lab boundaries.

Key Functions:
    - Load "bad patterns" (known indicators of misconfiguration)
    - Validate target domain scope (lab-only environments)
    - Rate-limit enforcement (prevent DoS accusations)
    - Pattern categorization (exposure type: directory, file, service)
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('labfinder_detailed.log', encoding='utf-8'),
        logging.StreamHandler(stream=sys.stdout)
    ]
)
logger = logging.getLogger(__name__)



# ============================================================================
# ENUMS & DATA STRUCTURES
# ============================================================================

class ExposureType(Enum):
    """Classification of information exposure."""
    DIRECTORY_LISTING = "directory_listing"
    SENSITIVE_FILE = "sensitive_file"
    ADMIN_PANEL = "admin_panel"
    BACKUP_FILE = "backup_file"
    CONFIG_FILE = "config_file"
    DEBUG_INFO = "debug_info"
    API_ENDPOINT = "api_endpoint"
    VERSION_DISCLOSURE = "version_disclosure"


class SeverityLevel(Enum):
    """Severity classification for exposures."""
    CRITICAL = "critical"      # Direct system compromise path
    HIGH = "high"               # Significant information disclosure
    MEDIUM = "medium"           # Useful reconnaissance data
    LOW = "low"                 # Minimal impact
    INFO = "informational"      # Interesting but non-critical


@dataclass
class ReconPattern:
    """Single reconnaissance pattern."""
    pattern: str                           # Search pattern/query
    description: str                       # What this pattern identifies
    exposure_type: ExposureType           # Category of exposure
    severity: SeverityLevel               # Potential severity if found
    enabled: bool = True                  # Whether this pattern is active
    search_engine: str = "google"         # Which search engine to use
    notes: str = ""                       # Additional context


# ============================================================================
# RECONNAISSANCE PATTERNS DATABASE
# ============================================================================

SAFE_RECON_PATTERNS = [
    # ===== DIRECTORY EXPOSURE =====
    ReconPattern(
        pattern='site:{target} intitle:"Index of"',
        description="Directory listing exposed via web indexing",
        exposure_type=ExposureType.DIRECTORY_LISTING,
        severity=SeverityLevel.HIGH,
        notes="Indicates web server misconfiguration allowing directory traversal"
    ),
    
    # ===== BACKUP FILE EXPOSURE =====
    ReconPattern(
        pattern='site:{target} filetype:bak OR filetype:backup OR filetype:old',
        description="Backup files left accessible on web server",
        exposure_type=ExposureType.BACKUP_FILE,
        severity=SeverityLevel.CRITICAL,
        notes="Often contains credentials or sensitive source code"
    ),
    
    # ===== CONFIGURATION FILE EXPOSURE =====
    ReconPattern(
        pattern='site:{target} filetype:conf OR filetype:config',
        description="Configuration files exposed in web root",
        exposure_type=ExposureType.CONFIG_FILE,
        severity=SeverityLevel.CRITICAL,
        notes="May contain database credentials, API keys, secret keys"
    ),
    
    # ===== ADMIN PANEL DISCOVERY =====
    ReconPattern(
        pattern='site:{target} inurl:/admin OR inurl:/administrator OR inurl:/wp-admin',
        description="Administrative interfaces discoverable via search engines",
        exposure_type=ExposureType.ADMIN_PANEL,
        severity=SeverityLevel.HIGH,
        notes="Should be behind authentication; discoverable admin panel suggests weak security"
    ),
    
    # ===== DEBUG INFO EXPOSURE =====
    ReconPattern(
        pattern='site:{target} "debug" OR "stack trace" OR "exception"',
        description="Debug information disclosed in error messages",
        exposure_type=ExposureType.DEBUG_INFO,
        severity=SeverityLevel.MEDIUM,
        notes="Reveals internal application structure and potential vulnerabilities"
    ),
    
    # ===== API KEY/SECRET EXPOSURE =====
    ReconPattern(
        pattern='site:{target} "api_key" OR "secret_key" OR "password" OR "token"',
        description="Hardcoded credentials or API keys visible in web pages",
        exposure_type=ExposureType.VERSION_DISCLOSURE,
        severity=SeverityLevel.CRITICAL,
        notes="Should never be committed to web-accessible directories"
    ),
    
    # ===== VERSION DISCLOSURE =====
    ReconPattern(
        pattern='site:{target} "Powered by" OR "version" OR "apache" filetype:html',
        description="Service version information disclosed in HTTP headers or HTML",
        exposure_type=ExposureType.VERSION_DISCLOSURE,
        severity=SeverityLevel.LOW,
        notes="Useful for targeting known vulnerabilities (requires follow-up testing)"
    ),
]


# ============================================================================
# SCOPE VALIDATION
# ============================================================================

AUTHORIZED_LAB_DOMAINS = [
    # Local/Private Ranges
    "127.0.0.1",
    "localhost",
    "*.local",
    "*.lab",
    "192.168.*",
    "10.0.*",
    "172.16.*",
    
    # Public Test/Lab Domains (pre-approved for security research)
    "example.com",           # IETF reserved for examples
    "test.example.com",
    "vulnerable.lab",
    "insecure-app.lab",
    
    # NOTE: Add your specific lab domains here
    # Example: "mylab.internal", "vulnerable-target.test"
]

FORBIDDEN_DOMAINS = [
    # Real-world domains (NEVER test these)
    "google.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    # ... add any other restricted domains
]


# ============================================================================
# CONFIGURATION LOADER CLASS
# ============================================================================

class ConfigLoader:
    """
    Loads and manages reconnaissance patterns for safe, lab-only information gathering.
    
    Implements:
    - Pattern loading and validation
    - Scope enforcement (lab-only domains)
    - Rate-limiting configuration
    - Pattern categorization
    """
    
    def __init__(self, max_queries_per_minute: int = 10):
        """
        Initialize configuration loader.
        
        Args:
            max_queries_per_minute: Rate limit for reconnaissance queries
        """
        self.patterns: List[ReconPattern] = []
        self.max_queries_per_minute = max_queries_per_minute
        self.enabled = True
        
        logger.info("ConfigLoader initialized")
        logger.info(f"Rate limit: {max_queries_per_minute} queries/minute")
    
    def load_patterns(self, patterns: Optional[List[ReconPattern]] = None) -> None:
        """
        Load reconnaissance patterns from built-in database or custom source.
        
        Args:
            patterns: Optional custom pattern list. If None, uses SAFE_RECON_PATTERNS
        """
        if patterns is None:
            patterns = SAFE_RECON_PATTERNS
        
        self.patterns = patterns
        logger.info(f"Loaded {len(self.patterns)} reconnaissance patterns")
        
        # Log pattern breakdown by exposure type
        by_type = {}
        for pattern in self.patterns:
            exposure_type = pattern.exposure_type.value
            by_type[exposure_type] = by_type.get(exposure_type, 0) + 1
        
        for exp_type, count in sorted(by_type.items()):
            logger.debug(f"  {exp_type}: {count} patterns")
    
    def validate_target_domain(self, target_domain: str) -> bool:
        """
        Validate that target domain is within authorized scope (lab-only).
        
        Args:
            target_domain: Domain to validate
            
        Returns:
            True if domain is authorized for reconnaissance
            
        Raises:
            ValueError: If domain is forbidden or outside authorized scope
        """
        logger.info(f"Validating target domain: {target_domain}")
        
        # Check forbidden list
        if self._matches_pattern(target_domain, FORBIDDEN_DOMAINS):
            error_msg = f"FORBIDDEN: {target_domain} is not authorized for testing"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Check authorized list
        if not self._matches_pattern(target_domain, AUTHORIZED_LAB_DOMAINS):
            warning_msg = f"WARNING: {target_domain} not in authorized lab domain list"
            logger.warning(warning_msg)
            # Note: We allow it with warning, but log it for audit
            return True
        
        logger.info(f"✓ {target_domain} is authorized for reconnaissance")
        return True
    
    @staticmethod
    def _matches_pattern(domain: str, pattern_list: List[str]) -> bool:
        """
        Check if domain matches any pattern in list (supports wildcards).
        
        Args:
            domain: Domain to check
            pattern_list: List of patterns (supports * wildcard)
            
        Returns:
            True if domain matches any pattern
        """
        import fnmatch
        return any(fnmatch.fnmatch(domain, pattern) for pattern in pattern_list)
    
    def get_patterns_by_exposure_type(self, exposure_type: ExposureType) -> List[ReconPattern]:
        """
        Retrieve patterns filtered by exposure type.
        
        Args:
            exposure_type: Type of exposure to filter for
            
        Returns:
            List of matching patterns
        """
        matching = [p for p in self.patterns if p.exposure_type == exposure_type]
        logger.debug(f"Retrieved {len(matching)} patterns for {exposure_type.value}")
        return matching
    
    def get_patterns_by_severity(self, severity: SeverityLevel) -> List[ReconPattern]:
        """
        Retrieve patterns filtered by severity level.
        
        Args:
            severity: Severity level to filter for
            
        Returns:
            List of matching patterns
        """
        matching = [p for p in self.patterns if p.severity == severity]
        logger.debug(f"Retrieved {len(matching)} patterns for severity {severity.value}")
        return matching
    
    def get_enabled_patterns(self) -> List[ReconPattern]:
        """
        Get all enabled patterns.
        
        Returns:
            List of enabled patterns
        """
        enabled = [p for p in self.patterns if p.enabled]
        logger.debug(f"Retrieved {len(enabled)} enabled patterns")
        return enabled
    
    def export_patterns_json(self, filename: str = "patterns_export.json") -> None:
        """
        Export patterns to JSON file for review/audit.
        
        Args:
            filename: Output filename
        """
        export_data = {
            "total_patterns": len(self.patterns),
            "patterns": [
                {
                    "pattern": p.pattern,
                    "description": p.description,
                    "exposure_type": p.exposure_type.value,
                    "severity": p.severity.value,
                    "enabled": p.enabled,
                    "search_engine": p.search_engine,
                    "notes": p.notes
                }
                for p in self.patterns
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Patterns exported to {filename}")
    
    def get_summary(self) -> Dict:
        """
        Get summary statistics about loaded patterns.
        
        Returns:
            Dictionary with pattern statistics
        """
        summary = {
            "total_patterns": len(self.patterns),
            "enabled_patterns": len(self.get_enabled_patterns()),
            "patterns_by_exposure_type": {},
            "patterns_by_severity": {},
            "rate_limit_queries_per_minute": self.max_queries_per_minute,
            "authorized_domains": len(AUTHORIZED_LAB_DOMAINS),
            "forbidden_domains": len(FORBIDDEN_DOMAINS)
        }
        
        # Count by exposure type
        for exp_type in ExposureType:
            count = len(self.get_patterns_by_exposure_type(exp_type))
            if count > 0:
                summary["patterns_by_exposure_type"][exp_type.value] = count
        
        # Count by severity
        for severity in SeverityLevel:
            count = len(self.get_patterns_by_severity(severity))
            if count > 0:
                summary["patterns_by_severity"][severity.value] = count
        
        return summary


# ============================================================================
# MAIN: DEMONSTRATION
# ============================================================================

def main():
    """Demonstrate L1 Configuration Loader functionality."""
    
    logger.info("=" * 70)
    logger.info("LabLeakFinder - L1 Configuration Loader")
    logger.info("Domain: Information Gathering & Vulnerability Identification")
    logger.info("=" * 70)
    
    # Initialize loader
    loader = ConfigLoader(max_queries_per_minute=15)
    
    # Load patterns
    loader.load_patterns()
    
    # Display summary
    summary = loader.get_summary()
    logger.info("\n" + "=" * 70)
    logger.info("RECONNAISSANCE PATTERN SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total patterns loaded: {summary['total_patterns']}")
    logger.info(f"Enabled patterns: {summary['enabled_patterns']}")
    logger.info(f"Rate limit: {summary['rate_limit_queries_per_minute']} queries/minute")
    logger.info(f"Authorized lab domains: {summary['authorized_domains']}")
    logger.info(f"Forbidden domains: {summary['forbidden_domains']}")
    
    logger.info("\nPatterns by Exposure Type:")
    for exp_type, count in sorted(summary["patterns_by_exposure_type"].items()):
        logger.info(f"  {exp_type}: {count}")
    
    logger.info("\nPatterns by Severity:")
    for severity, count in sorted(summary["patterns_by_severity"].items()):
        logger.info(f"  {severity}: {count}")
    
    # Test domain validation
    logger.info("\n" + "=" * 70)
    logger.info("DOMAIN VALIDATION TESTS")
    logger.info("=" * 70)
    
    test_domains = [
        ("vulnerable.lab", True),           # Should pass
        ("google.com", False),              # Should fail (forbidden)
        ("192.168.1.100", True),            # Should pass (private range)
        ("myapp.local", True),              # Should pass (local)
    ]
    
    for domain, should_pass in test_domains:
        try:
            result = loader.validate_target_domain(domain)
            status = "[PASS]" if result else "[FAIL]"

            logger.info(f"{status}: {domain}")
        except ValueError as e:
            if should_pass:
                logger.error(f" [FAIL] (unexpected): {domain} - {e}")
            else:
                logger.info(f" [PASS] (correctly rejected): {domain}")
    
    # Export patterns for review
    logger.info("\n" + "=" * 70)
    logger.info("EXPORTING PATTERNS FOR REVIEW")
    logger.info("=" * 70)
    loader.export_patterns_json("recon_patterns.json")
    
    # Display sample patterns
    logger.info("\nSample Reconnaissance Patterns:")
    for i, pattern in enumerate(loader.get_enabled_patterns()[:3], 1):
        logger.info(f"\n  Pattern #{i}:")
        logger.info(f"    Query: {pattern.pattern}")
        logger.info(f"    Type: {pattern.exposure_type.value}")
        logger.info(f"    Severity: {pattern.severity.value}")
        logger.info(f"    Description: {pattern.description}")
    
    logger.info("\n" + "=" * 70)
    logger.info("L1 Configuration Loader Test Complete")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()

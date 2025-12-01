"""
LabLeakFinder L2: Query Formatter
Domain: Information Gathering & Vulnerability Identification (PenTest+ Domain 2)

Purpose:
    Format reconnaissance patterns into safe, rate-limited queries.
    Binds patterns to target domains and logs query metadata.

Key Functions:
    - Pattern-to-query binding (replace {target} placeholder)
    - Rate-limiting enforcement (queries per minute)
    - Query safety validation
    - Query metadata generation
    - Audit logging (JSON export)

Integration:
    INPUT: L1 Configuration Loader (patterns + domain)
    OUTPUT: Formatted queries -> L3 Result Analyzer
"""

import json
import logging
import sys
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import deque
from enum import Enum

try:
    from l1_config_loader import (
        ConfigLoader, ReconPattern, ExposureType, SeverityLevel
    )
except ImportError:
    print("[ERROR] l1_config_loader.py not found.")
    sys.exit(1)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('labfinder_l2_detailed.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SearchEngine(Enum):
    """Supported search engines for reconnaissance."""
    GOOGLE = "google"
    BING = "bing"
    DUCKDUCKGO = "duckduckgo"

class QueryStatus(Enum):
    """Status of a formatted query."""
    FORMATTED = "formatted"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_DOMAIN = "invalid_domain"
    UNSAFE_QUERY = "unsafe_query"
    READY = "ready"

@dataclass
class FormattedQuery:
    """A formatted reconnaissance query."""
    query_id: int
    timestamp: str
    target_domain: str
    pattern_id: int
    pattern_description: str
    query_string: str
    exposure_type: str
    severity: str
    search_engine: str
    query_status: str
    rate_limit_ok: bool = True
    safety_validated: bool = True
    notes: str = ""

class RateLimiter:
    """Token bucket rate limiter for queries per minute."""
    
    def __init__(self, max_queries_per_minute: int):
        self.max_queries_per_minute = max_queries_per_minute
        self.query_timestamps = deque()
        self.logger = logging.getLogger(f"{__name__}.RateLimiter")
    
    def is_allowed(self) -> bool:
        now = time.time()
        minute_ago = now - 60
        
        while self.query_timestamps and self.query_timestamps[0] < minute_ago:
            self.query_timestamps.popleft()
        
        if len(self.query_timestamps) < self.max_queries_per_minute:
            self.query_timestamps.append(now)
            self.logger.debug(
                f"Query allowed ({len(self.query_timestamps)}/{self.max_queries_per_minute} in last minute)"
            )
            return True
        else:
            self.logger.warning(
                f"Rate limit exceeded ({len(self.query_timestamps)}/{self.max_queries_per_minute})"
            )
            return False
    
    def get_status(self) -> Dict:
        now = time.time()
        minute_ago = now - 60
        
        recent = sum(1 for ts in self.query_timestamps if ts > minute_ago)
        
        return {
            "queries_this_minute": recent,
            "max_queries_per_minute": self.max_queries_per_minute,
            "queries_remaining": max(0, self.max_queries_per_minute - recent)
        }

class QueryFormatter:
    """
    Formats reconnaissance patterns into safe, rate-limited queries.
    
    Implements:
    - Pattern-to-query binding ({target} replacement)
    - Rate-limiting enforcement
    - Query safety validation
    - Query metadata generation
    - Audit logging
    """
    
    def __init__(self, max_queries_per_minute: int = 15):
        self.config_loader = ConfigLoader(max_queries_per_minute)
        self.config_loader.load_patterns()
        self.rate_limiter = RateLimiter(max_queries_per_minute)
        self.query_counter = 0
        self.queries = []
        
        logger.info("QueryFormatter initialized")
        logger.info(f"Rate limit: {max_queries_per_minute} queries/minute")
    
    def validate_domain(self, target_domain: str) -> bool:
        return self.config_loader.validate_target_domain(target_domain)
    
    def format_query(
        self,
        pattern: ReconPattern,
        target_domain: str,
        search_engine: SearchEngine = SearchEngine.GOOGLE
    ) -> Optional[FormattedQuery]:
        """Format a single reconnaissance query."""
        logger.debug(f"Formatting query for {target_domain} using pattern: {pattern.description}")
        
        if not self.rate_limiter.is_allowed():
            logger.warning(f"Rate limit exceeded. Query not formatted.")
            return FormattedQuery(
                query_id=self.query_counter + 1,
                timestamp=datetime.utcnow().isoformat(),
                target_domain=target_domain,
                pattern_id=id(pattern),
                pattern_description=pattern.description,
                query_string="",
                exposure_type=pattern.exposure_type.value,
                severity=pattern.severity.value,
                search_engine=search_engine.value,
                query_status=QueryStatus.RATE_LIMIT_EXCEEDED.value,
                rate_limit_ok=False,
                notes="Rate limit exceeded"
            )
        
        try:
            self.validate_domain(target_domain)
        except ValueError as e:
            logger.error(f"Domain validation failed: {e}")
            return FormattedQuery(
                query_id=self.query_counter + 1,
                timestamp=datetime.utcnow().isoformat(),
                target_domain=target_domain,
                pattern_id=id(pattern),
                pattern_description=pattern.description,
                query_string="",
                exposure_type=pattern.exposure_type.value,
                severity=pattern.severity.value,
                search_engine=search_engine.value,
                query_status=QueryStatus.INVALID_DOMAIN.value,
                rate_limit_ok=True,
                safety_validated=False,
                notes=str(e)
            )
        
        query_string = pattern.pattern.format(target=target_domain)
        
        if not self._is_safe_query(query_string):
            logger.warning(f"Query failed safety validation: {query_string}")
            return FormattedQuery(
                query_id=self.query_counter + 1,
                timestamp=datetime.utcnow().isoformat(),
                target_domain=target_domain,
                pattern_id=id(pattern),
                pattern_description=pattern.description,
                query_string=query_string,
                exposure_type=pattern.exposure_type.value,
                severity=pattern.severity.value,
                search_engine=search_engine.value,
                query_status=QueryStatus.UNSAFE_QUERY.value,
                rate_limit_ok=True,
                safety_validated=False,
                notes="Query contains potentially unsafe characters"
            )
        
        self.query_counter += 1
        formatted_query = FormattedQuery(
            query_id=self.query_counter,
            timestamp=datetime.utcnow().isoformat(),
            target_domain=target_domain,
            pattern_id=id(pattern),
            pattern_description=pattern.description,
            query_string=query_string,
            exposure_type=pattern.exposure_type.value,
            severity=pattern.severity.value,
            search_engine=search_engine.value,
            query_status=QueryStatus.FORMATTED.value,
            rate_limit_ok=True,
            safety_validated=True
        )
        
        self.queries.append(formatted_query)
        logger.info(f"[Query #{self.query_counter}] Formatted: {pattern.description} on {target_domain}")
        
        return formatted_query
    
    @staticmethod
    def _is_safe_query(query_string: str) -> bool:
        """Validate that query string is safe for execution."""
        dangerous_patterns = [
            ";",
            "&&",
            "||",
            "`",
            "$("]
        
        for dangerous in dangerous_patterns:
            if dangerous in query_string:
                return False
        
        return True
    
    def format_queries_for_domain(
        self,
        target_domain: str,
        severity_filter: Optional[SeverityLevel] = None,
        exposure_type_filter: Optional[ExposureType] = None
    ) -> List[FormattedQuery]:
        """Format all patterns as queries for a single target domain."""
        logger.info(f"Formatting all patterns for domain: {target_domain}")
        
        if severity_filter:
            patterns = self.config_loader.get_patterns_by_severity(severity_filter)
        elif exposure_type_filter:
            patterns = self.config_loader.get_patterns_by_exposure_type(exposure_type_filter)
        else:
            patterns = self.config_loader.get_enabled_patterns()
        
        formatted_queries = []
        for pattern in patterns:
            formatted_query = self.format_query(pattern, target_domain)
            if formatted_query:
                formatted_queries.append(formatted_query)
        
        logger.info(f"Formatted {len(formatted_queries)} queries for {target_domain}")
        return formatted_queries
    
    def export_queries_json(self, filename: str = "formatted_queries.json") -> None:
        """Export all formatted queries to JSON file."""
        export_data = {
            "total_queries": len(self.queries),
            "queries": [asdict(q) for q in self.queries]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(self.queries)} queries to {filename}")
    
    def get_summary(self) -> Dict:
        """Get summary statistics about formatted queries."""
        successful = sum(1 for q in self.queries if q.query_status == QueryStatus.FORMATTED.value)
        rate_limited = sum(1 for q in self.queries if q.query_status == QueryStatus.RATE_LIMIT_EXCEEDED.value)
        invalid_domain = sum(1 for q in self.queries if q.query_status == QueryStatus.INVALID_DOMAIN.value)
        unsafe = sum(1 for q in self.queries if q.query_status == QueryStatus.UNSAFE_QUERY.value)
        
        return {
            "total_queries": len(self.queries),
            "successful": successful,
            "rate_limited": rate_limited,
            "invalid_domain": invalid_domain,
            "unsafe_queries": unsafe,
            "rate_limit_status": self.rate_limiter.get_status()
        }

def main():
    """Demonstrate L2 Query Formatter functionality."""
    
    logger.info("=" * 80)
    logger.info("LabLeakFinder - L2 Query Formatter")
    logger.info("Domain: Information Gathering & Vulnerability Identification")
    logger.info("=" * 80)
    
    formatter = QueryFormatter(max_queries_per_minute=20)
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST 1: Format queries for single domain (vulnerable.lab)")
    logger.info("=" * 80)
    
    test_domain = "vulnerable.lab"
    try:
        queries = formatter.format_queries_for_domain(test_domain)
        
        logger.info(f"\nFormatted {len(queries)} queries for {test_domain}:\n")
        
        for query in queries:
            if query.query_status == QueryStatus.FORMATTED.value:
                logger.info(f"[Query #{query.query_id}] {query.pattern_description}")
                logger.info(f"  Exposure Type: {query.exposure_type}")
                logger.info(f"  Severity: {query.severity}")
                logger.info(f"  Query: {query.query_string}\n")
    
    except ValueError as e:
        logger.error(f"Failed to format queries: {e}")
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST 2: Attempt to format for forbidden domain (google.com)")
    logger.info("=" * 80)
    
    forbidden_domain = "google.com"
    try:
        queries = formatter.format_queries_for_domain(forbidden_domain)
        
        for query in queries:
            if query.query_status != QueryStatus.FORMATTED.value:
                logger.info(f"[Correctly Blocked] {forbidden_domain}")
                logger.info(f"  Status: {query.query_status}")
                logger.info(f"  Notes: {query.notes}\n")
    
    except ValueError as e:
        logger.info(f"[Correctly Rejected] {forbidden_domain} - {e}\n")
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST 3: Filter queries by severity (CRITICAL only)")
    logger.info("=" * 80)
    
    try:
        critical_queries = formatter.format_queries_for_domain(
            test_domain,
            severity_filter=SeverityLevel.CRITICAL
        )
        
        logger.info(f"Formatted {len(critical_queries)} CRITICAL-level queries:\n")
        
        for query in critical_queries:
            if query.query_status == QueryStatus.FORMATTED.value:
                logger.info(f"[CRITICAL] {query.pattern_description}")
                logger.info(f"  Query: {query.query_string}\n")
    
    except Exception as e:
        logger.error(f"Failed: {e}")
    
    logger.info("\n" + "=" * 80)
    logger.info("SUMMARY")
    logger.info("=" * 80)
    
    summary = formatter.get_summary()
    logger.info(f"Total queries formatted: {summary['total_queries']}")
    logger.info(f"Successful: {summary['successful']}")
    logger.info(f"Rate limited: {summary['rate_limited']}")
    logger.info(f"Invalid domain: {summary['invalid_domain']}")
    logger.info(f"Unsafe queries: {summary['unsafe_queries']}")
    
    rate_status = summary['rate_limit_status']
    logger.info(f"\nRate Limit Status:")
    logger.info(f"  Queries this minute: {rate_status['queries_this_minute']}/{rate_status['max_queries_per_minute']}")
    logger.info(f"  Queries remaining: {rate_status['queries_remaining']}")
    
    logger.info("\n" + "=" * 80)
    logger.info("EXPORTING QUERIES")
    logger.info("=" * 80)
    
    formatter.export_queries_json("formatted_queries.json")
    
    logger.info("\n" + "=" * 80)
    logger.info("L2 Query Formatter Test Complete")
    logger.info("=" * 80)

if __name__ == "__main__":
    main()

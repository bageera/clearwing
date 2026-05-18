"""Intelligence correlation engine for OSINT data.

This module provides capabilities for correlating findings from multiple OSINT sources
to identify relationships and patterns in the collected data.
"""

import json
import logging
from typing import Any, Dict, List, Set
from collections import defaultdict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class IntelCorrelator:
    """Intelligence correlation engine for OSINT findings."""
    
    def __init__(self):
        """Initialize the intelligence correlator."""
        self.findings = defaultdict(list)
        self.relationships = defaultdict(set)
        
    def add_findings(self, source: str, findings: List[Dict[str, Any]]) -> None:
        """Add findings from a specific source.
        
        Args:
            source: Source identifier (e.g., 'amass', 'crt_sh')
            findings: List of finding dictionaries
        """
        self.findings[source].extend(findings)
        logger.debug(f"Added {len(findings)} findings from {source}")
        
    def correlate_subdomains_and_ips(self) -> Dict[str, Any]:
        """Correlate subdomains with IP addresses across sources.
        
        Returns:
            Dictionary with correlation results
        """
        # Extract subdomains and IPs from all sources
        subdomain_sources = defaultdict(set)
        ip_sources = defaultdict(set)
        
        # Process findings from each source
        for source, findings in self.findings.items():
            for finding in findings:
                # Extract subdomains
                if 'subdomain' in finding:
                    subdomain_sources[finding['subdomain']].add(source)
                elif 'subdomains' in finding:
                    for subdomain in finding['subdomains']:
                        subdomain_sources[subdomain].add(source)
                        
                # Extract IPs
                if 'ip' in finding:
                    ip_sources[finding['ip']].add(source)
                elif 'ips' in finding:
                    for ip in finding['ips']:
                        ip_sources[ip].add(source)
                        
        # Identify unique and overlapping findings
        unique_subdomains = {sub: sources for sub, sources in subdomain_sources.items() if len(sources) == 1}
        overlapping_subdomains = {sub: sources for sub, sources in subdomain_sources.items() if len(sources) > 1}
        
        unique_ips = {ip: sources for ip, sources in ip_sources.items() if len(sources) == 1}
        overlapping_ips = {ip: sources for ip, sources in ip_sources.items() if len(sources) > 1}
        
        return {
            'subdomain_correlation': {
                'total_unique': len(unique_subdomains),
                'total_overlapping': len(overlapping_subdomains),
                'unique_subdomains': dict(unique_subdomains),
                'overlapping_subdomains': {sub: list(sources) for sub, sources in overlapping_subdomains.items()}
            },
            'ip_correlation': {
                'total_unique': len(unique_ips),
                'total_overlapping': len(overlapping_ips),
                'unique_ips': dict(unique_ips),
                'overlapping_ips': {ip: list(sources) for ip, sources in overlapping_ips.items()}
            }
        }
        
    def correlate_domains_and_urls(self) -> Dict[str, Any]:
        """Correlate domains with URLs and identify web technologies.
        
        Returns:
            Dictionary with domain-URL correlation results
        """
        domain_urls = defaultdict(set)
        url_technologies = defaultdict(set)
        
        # Process URL findings
        for source, findings in self.findings.items():
            for finding in findings:
                if 'url' in finding:
                    urls = [finding['url']]
                elif 'urls' in finding:
                    urls = finding['urls']
                else:
                    continue
                    
                for url in urls:
                    try:
                        parsed = urlparse(url)
                        domain = parsed.netloc
                        domain_urls[domain].add(url)
                        
                        # Extract technology hints from URL structure
                        if '/wp-' in url or '/wordpress/' in url:
                            url_technologies[url].add('wordpress')
                        if '.asp' in url:
                            url_technologies[url].add('asp')
                        if '.jsp' in url:
                            url_technologies[url].add('java')
                        if '.php' in url:
                            url_technologies[url].add('php')
                    except Exception:
                        pass  # Skip malformed URLs
                        
        return {
            'domain_url_mapping': {domain: list(urls) for domain, urls in domain_urls.items()},
            'technology_hints': {url: list(techs) for url, techs in url_technologies.items()},
            'statistics': {
                'total_domains': len(domain_urls),
                'total_urls': sum(len(urls) for urls in domain_urls.values())
            }
        }
        
    def identify_infrastructure_patterns(self) -> Dict[str, Any]:
        """Identify common infrastructure patterns like cloud services.
        
        Returns:
            Dictionary with identified infrastructure patterns
        """
        cloud_patterns = {
            'aws': ['.amazonaws.com', '.s3.', 'ec2-', 'cloudfront'],
            'azure': ['.azure.com', '.windows.net', 'azurewebsites'],
            'gcp': ['.googleapis.com', '.appspot.com', 'storage.googleapis'],
            'cloudflare': ['.cloudflare.com', '.pages.dev'],
            'github': ['.github.io', 'github.com'],
        }
        
        identified_services = defaultdict(list)
        
        # Check all subdomains and domains
        all_domains = set()
        for findings in self.findings.values():
            for finding in findings:
                if 'subdomain' in finding:
                    all_domains.add(finding['subdomain'])
                elif 'subdomains' in finding:
                    all_domains.update(finding['subdomains'])
                elif 'domain' in finding:
                    all_domains.add(finding['domain'])
                elif 'domains' in finding:
                    all_domains.update(finding['domains'])
                    
        # Identify cloud services
        for domain in all_domains:
            for service, patterns in cloud_patterns.items():
                for pattern in patterns:
                    if pattern in domain:
                        identified_services[service].append(domain)
                        break
                        
        return {
            'cloud_services': {service: list(domains) for service, domains in identified_services.items()},
            'total_cloud_domains': sum(len(domains) for domains in identified_services.values()),
            'coverage_percentage': round(
                (sum(len(domains) for domains in identified_services.values()) / len(all_domains) * 100) 
                if all_domains else 0, 2
            )
        }
        
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate a comprehensive correlation report.
        
        Returns:
            Dictionary with comprehensive correlation analysis
        """
        logger.info("Generating comprehensive correlation report")
        
        report = {
            'summary': {
                'total_sources': len(self.findings),
                'total_findings': sum(len(findings) for findings in self.findings.values()),
                'sources_list': list(self.findings.keys())
            },
            'subdomain_ip_correlation': self.correlate_subdomains_and_ips(),
            'domain_url_correlation': self.correlate_domains_and_urls(),
            'infrastructure_patterns': self.identify_infrastructure_patterns()
        }
        
        # Add overall statistics
        report['statistics'] = {
            'unique_subdomains': len(report['subdomain_ip_correlation']['subdomain_correlation']['unique_subdomains']),
            'overlapping_subdomains': len(report['subdomain_ip_correlation']['subdomain_correlation']['overlapping_subdomains']),
            'unique_ips': len(report['subdomain_ip_correlation']['ip_correlation']['unique_ips']),
            'overlapping_ips': len(report['subdomain_ip_correlation']['ip_correlation']['overlapping_ips']),
            'total_domains': report['domain_url_correlation']['statistics']['total_domains'],
            'total_urls': report['domain_url_correlation']['statistics']['total_urls'],
            'cloud_coverage': report['infrastructure_patterns']['coverage_percentage']
        }
        
        logger.info("Comprehensive correlation report generated")
        return report


def correlate_osint_findings(findings_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """High-level function to correlate OSINT findings from multiple sources.
    
    Args:
        findings_data: Dictionary mapping source names to lists of findings
        
    Returns:
        Dictionary with correlation analysis and insights
    """
    correlator = IntelCorrelator()
    
    # Add all findings to the correlator
    for source, findings in findings_data.items():
        correlator.add_findings(source, findings)
        
    # Generate comprehensive report
    return correlator.generate_comprehensive_report()
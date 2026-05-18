"""Structured Output Parsers for Reconnaissance Tools.

This module provides parsers for converting raw tool output into structured data
that can be easily stored and analyzed.
"""

import json
import xml.etree.ElementTree as ET
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def parse_nmap_xml(xml_output: str) -> Dict[str, Any]:
    """Parse Nmap XML output into structured data.
    
    Args:
        xml_output: Raw XML output from nmap
        
    Returns:
        Dict containing structured host information
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"error": f"Failed to parse XML: {str(e)}"}
    
    hosts = []
    for host_elem in root.findall('host'):
        host_data = {}
        
        # Get host status
        status_elem = host_elem.find('status')
        if status_elem is not None:
            host_data['status'] = status_elem.get('state', 'unknown')
            
        # Get addresses
        addresses = []
        for addr_elem in host_elem.findall('address'):
            addr_data = {
                'addr': addr_elem.get('addr'),
                'addrtype': addr_elem.get('addrtype')
            }
            addresses.append(addr_data)
        host_data['addresses'] = addresses
        
        # Get hostnames
        hostnames = []
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for name_elem in hostnames_elem.findall('hostname'):
                hostnames.append({
                    'name': name_elem.get('name'),
                    'type': name_elem.get('type')
                })
        host_data['hostnames'] = hostnames
        
        # Get ports
        ports = []
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port_data = {
                    'portid': port_elem.get('portid'),
                    'protocol': port_elem.get('protocol'),
                    'state': None,
                    'service': None
                }
                
                # Get port state
                state_elem = port_elem.find('state')
                if state_elem is not None:
                    port_data['state'] = state_elem.get('state')
                    
                # Get service info
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    port_data['service'] = {
                        'name': service_elem.get('name'),
                        'product': service_elem.get('product'),
                        'version': service_elem.get('version'),
                        'extrainfo': service_elem.get('extrainfo')
                    }
                ports.append(port_data)
        host_data['ports'] = ports
        
        hosts.append(host_data)
        
    return {
        'hosts': hosts,
        'scan_info': {
            'version': root.get('version'),
            'start_time': root.get('start'),
        }
    }


def parse_theharvester_xml(xml_output: str) -> Dict[str, Any]:
    """Parse theHarvester XML output into structured data.
    
    Args:
        xml_output: Raw XML output from theHarvester
        
    Returns:
        Dict containing structured email and host information
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"error": f"Failed to parse XML: {str(e)}"}
    
    # Parse emails
    emails = []
    emails_elem = root.find('emails')
    if emails_elem is not None:
        for email_elem in emails_elem.findall('email'):
            emails.append(email_elem.text)
            
    # Parse hosts
    hosts = []
    hosts_elem = root.find('hosts')
    if hosts_elem is not None:
        for host_elem in hosts_elem.findall('host'):
            hosts.append(host_elem.text)
            
    # Parse ips
    ips = []
    ips_elem = root.find('ips')
    if ips_elem is not None:
        for ip_elem in ips_elem.findall('ip'):
            ips.append(ip_elem.text)
            
    return {
        'emails': list(set(emails)),  # Remove duplicates
        'hosts': list(set(hosts)),
        'ips': list(set(ips)),
        'asns': [],  # Placeholder for ASN info if available
    }


def parse_amass_json(json_output: str) -> Dict[str, Any]:
    """Parse Amass JSON output into structured data.
    
    Args:
        json_output: Raw JSON output from Amass
        
    Returns:
        Dict containing structured subdomain and IP information
    """
    try:
        # Amass output might be multiple JSON objects separated by newlines
        lines = json_output.strip().split('\n')
        data = []
        for line in lines:
            if line.strip():
                data.append(json.loads(line))
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse JSON: {str(e)}"}
    
    subdomains = []
    ips = []
    
    for entry in data:
        # Extract subdomains
        if 'name' in entry:
            subdomains.append(entry['name'])
            
        # Extract IPs
        if 'addresses' in entry:
            for addr in entry['addresses']:
                if 'ip' in addr:
                    ips.append(addr['ip'])
                    
    return {
        'subdomains': list(set(subdomains)),  # Remove duplicates
        'ips': list(set(ips)),
        'total_entries': len(data)
    }


def parse_subfinder_json(json_output: str) -> Dict[str, Any]:
    """Parse Subfinder JSON output into structured data.
    
    Args:
        json_output: Raw JSON output from Subfinder
        
    Returns:
        Dict containing structured subdomain information
    """
    try:
        # Subfinder output might be multiple JSON objects separated by newlines
        lines = json_output.strip().split('\n')
        subdomains = []
        
        for line in lines:
            if line.strip():
                entry = json.loads(line)
                if 'host' in entry:
                    subdomains.append(entry['host'])
                elif 'matched' in entry:
                    subdomains.append(entry['matched'])
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse JSON: {str(e)}"}
    
    return {
        'subdomains': list(set(subdomains)),  # Remove duplicates
        'total_found': len(set(subdomains))
    }


def parse_github_json(json_output: str) -> Dict[str, Any]:
    """Parse GitHub API JSON output into structured data.
    
    Args:
        json_output: Raw JSON output from GitHub API
        
    Returns:
        Dict containing structured GitHub search results
    """
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse JSON: {str(e)}"}
    
    # Parse code search results
    if 'items' in data:
        results = []
        for item in data['items']:
            results.append({
                'name': item.get('name'),
                'path': item.get('path'),
                'repository': item.get('repository', {}).get('full_name'),
                'html_url': item.get('html_url'),
                'score': item.get('score')
            })
        return {
            'total_count': data.get('total_count', 0),
            'incomplete_results': data.get('incomplete_results', False),
            'items': results
        }
    
    return data


def parse_wayback_json(json_output: str) -> Dict[str, Any]:
    """Parse Wayback Machine output into structured data.
    
    Args:
        json_output: Raw JSON output from Wayback Machine
        
    Returns:
        Dict containing structured archived URLs
    """
    urls = []
    try:
        # Wayback output is typically one URL per line
        lines = json_output.strip().split('\n')
        for line in lines:
            if line.strip():
                # Try to parse as JSON first (some APIs return JSON)
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict) and 'url' in entry:
                        urls.append(entry['url'])
                    else:
                        urls.append(line.strip())
                except json.JSONDecodeError:
                    # If not JSON, treat as plain URL
                    urls.append(line.strip())
    except Exception as e:
        return {"error": f"Failed to parse Wayback output: {str(e)}"}
    
    # Extract additional information from URLs
    parsed_urls = []
    domains = set()
    paths = set()
    
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            domains.add(domain)
            paths.add(path)
            
            parsed_urls.append({
                'url': url,
                'domain': domain,
                'path': path,
                'scheme': parsed.scheme
            })
        except Exception:
            # If parsing fails, just add the raw URL
            parsed_urls.append({'url': url})
    
    return {
        'urls': parsed_urls,
        'unique_domains': list(domains),
        'unique_paths': list(paths),
        'total_urls': len(parsed_urls)
    }


def parse_assetfinder_output(output: str) -> Dict[str, Any]:
    """Parse assetfinder output into structured data.
    
    Args:
        output: Raw output from assetfinder
        
    Returns:
        Dict containing structured subdomain information
    """
    lines = output.strip().split('\n')
    subdomains = []
    
    for line in lines:
        if line.strip():
            # Clean up the line
            clean_line = line.strip().lstrip('*.')
            if clean_line:
                subdomains.append(clean_line)
                
    return {
        'subdomains': list(set(subdomains)),  # Remove duplicates
        'total_found': len(set(subdomains))
    }


def parse_findomain_output(output: str) -> Dict[str, Any]:
    """Parse findomain output into structured data.
    
    Args:
        output: Raw output from findomain
        
    Returns:
        Dict containing structured subdomain information
    """
    lines = output.strip().split('\n')
    subdomains = []
    
    for line in lines:
        if line.strip():
            # Findomain outputs CSV with subdomain as first column
            parts = line.split(',')
            if parts and parts[0].strip():
                subdomain = parts[0].strip().lstrip('*.')
                if subdomain:
                    subdomains.append(subdomain)
                    
    return {
        'subdomains': list(set(subdomains)),  # Remove duplicates
        'total_found': len(set(subdomains))
    }


def extract_technologies_from_html(html_content: str) -> Dict[str, Any]:
    """Extract technology fingerprints from HTML content.
    
    Args:
        html_content: Raw HTML content
        
    Returns:
        Dict containing detected technologies
    """
    technologies = []
    
    # Look for common technology indicators
    indicators = {
        'wordpress': [
            r'wp-content', 
            r'wp-includes', 
            r'WordPress',
            r'/wp-admin'
        ],
        'jquery': [
            r'jquery.*\.js',
            r'\$\(document\)\.ready'
        ],
        'bootstrap': [
            r'bootstrap.*\.css',
            r'bootstrap.*\.js',
            r'class=["\'].*bootstrap'
        ],
        'react': [
            r'react.*\.js',
            r'<div id="root">'
        ],
        'angular': [
            r'ng-app',
            r'angular.*\.js'
        ]
    }
    
    for tech, patterns in indicators.items():
        for pattern in patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                technologies.append(tech)
                break
                
    # Extract generator meta tag
    generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)', html_content, re.IGNORECASE)
    if generator_match:
        technologies.append(f"generator:{generator_match.group(1)}")
        
    # Extract server header indicators
    server_match = re.search(r'Server:\s*(.+)', html_content)
    if server_match:
        technologies.append(f"server:{server_match.group(1)}")
        
    return {
        'technologies': list(set(technologies)),
        'total_detected': len(set(technologies))
    }
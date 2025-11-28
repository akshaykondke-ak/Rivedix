"""
Common utility functions for Pentoolkit.
Validation, sanitization, parsing, and formatting helpers.
"""

import re
import ipaddress
import json
from typing import List, Optional, Any, Dict
from pathlib import Path
from urllib.parse import urlparse
import datetime


# ============================================================================
# TARGET VALIDATION
# ============================================================================

def is_valid_ip(target: str) -> bool:
    """
    Check if string is a valid IPv4 or IPv6 address.
    
    Examples:
        is_valid_ip("192.168.1.1") -> True
        is_valid_ip("example.com") -> False
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_domain(target: str) -> bool:
    """
    Check if string is a valid domain name.
    
    Examples:
        is_valid_domain("example.com") -> True
        is_valid_domain("sub.example.co.uk") -> True
        is_valid_domain("192.168.1.1") -> False
    """
    # Simple regex for domain validation
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, target))


def is_valid_url(target: str) -> bool:
    """
    Check if string is a valid URL.
    
    Examples:
        is_valid_url("https://example.com") -> True
        is_valid_url("example.com") -> False
    """
    try:
        result = urlparse(target)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_target(target: str) -> str:
    """
    Normalize a target to standard format.
    - Strips whitespace
    - Removes trailing slashes
    - Converts to lowercase (for domains)
    
    Examples:
        normalize_target(" Example.COM/ ") -> "example.com"
        normalize_target("HTTPS://Example.com/") -> "https://example.com"
    """
    target = target.strip().rstrip("/")
    
    # If it's a URL, preserve scheme case but lowercase domain
    if is_valid_url(target):
        parsed = urlparse(target)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
    
    # Otherwise just lowercase everything
    return target.lower()


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Examples:
        extract_domain_from_url("https://example.com:443/path") -> "example.com"
        extract_domain_from_url("http://sub.example.com") -> "sub.example.com"
    """
    try:
        parsed = urlparse(url)
        # Remove port if present
        domain = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
        return domain.lower()
    except Exception:
        return None


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is private/internal.
    
    Examples:
        is_private_ip("192.168.1.1") -> True
        is_private_ip("8.8.8.8") -> False
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private
    except ValueError:
        return False


def ip_in_range(ip_str: str, cidr_range: str) -> bool:
    """
    Check if IP is within a CIDR range.
    
    Examples:
        ip_in_range("192.168.1.50", "192.168.1.0/24") -> True
        ip_in_range("10.0.0.1", "192.168.1.0/24") -> False
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_range, strict=False)
        return ip_obj in network
    except ValueError:
        return False


# ============================================================================
# FILE & PATH UTILITIES
# ============================================================================

def ensure_directory(path: str | Path) -> Path:
    """
    Ensure directory exists, create if needed.
    
    Returns:
        Path object of the directory
    """
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    return path_obj


def safe_filename(name: str, max_length: int = 200) -> str:
    """
    Convert string to safe filename.
    - Removes unsafe characters
    - Replaces spaces with underscores
    - Truncates to max_length
    
    Examples:
        safe_filename("example.com/path?q=1") -> "example.com_path_q_1"
        safe_filename("Test File.txt") -> "test_file.txt"
    """
    # Remove/replace unsafe characters
    safe = re.sub(r'[^\w\s.-]', '_', name)
    safe = re.sub(r'\s+', '_', safe)
    safe = safe.strip('._')
    
    # Truncate if too long
    if len(safe) > max_length:
        safe = safe[:max_length]
    
    return safe.lower()


def read_targets_file(filepath: str) -> List[str]:
    """
    Read targets from file (one per line).
    - Skips empty lines
    - Strips whitespace
    - Removes comments (#)
    
    Returns:
        List of normalized targets
    """
    targets = []
    path = Path(filepath)
    
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {filepath}")
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            # Remove comments
            line = line.split('#')[0].strip()
            
            # Skip empty lines
            if not line:
                continue
            
            targets.append(normalize_target(line))
    
    return targets


def save_json(data: Any, filepath: str, indent: int = 2):
    """
    Save data to JSON file safely.
    Creates parent directories if needed.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def load_json(filepath: str) -> Any:
    """
    Load data from JSON file.
    Returns None if file doesn't exist or is invalid.
    """
    path = Path(filepath)
    
    if not path.exists():
        return None
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None


# ============================================================================
# DATA FORMATTING
# ============================================================================

def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.
    
    Examples:
        format_duration(45.2) -> "45.2s"
        format_duration(125.0) -> "2m 5s"
        format_duration(3665.0) -> "1h 1m 5s"
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    
    if minutes < 60:
        return f"{minutes}m {secs}s"
    
    hours = minutes // 60
    minutes = minutes % 60
    return f"{hours}h {minutes}m {secs}s"


def format_timestamp(dt: datetime.datetime = None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format timestamp in standard format.
    
    Args:
        dt: Datetime object (uses current time if None)
        fmt: Format string
    
    Returns:
        Formatted timestamp string
    """
    if dt is None:
        dt = datetime.datetime.now(datetime.UTC)
    return dt.strftime(fmt)


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to max length with suffix.
    
    Examples:
        truncate_string("Long text here", 10) -> "Long te..."
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def format_bytes(size: int) -> str:
    """
    Format byte size in human-readable format.
    
    Examples:
        format_bytes(1024) -> "1.0 KB"
        format_bytes(1048576) -> "1.0 MB"
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


# ============================================================================
# FINDING UTILITIES
# ============================================================================

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate findings based on title + description.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Deduplicated list
    """
    seen = set()
    unique = []
    
    for finding in findings:
        # Create fingerprint from title + description
        fingerprint = (
            finding.get("title", ""),
            finding.get("description", "")
        )
        
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique.append(finding)
    
    return unique


def sort_findings_by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort findings by severity (critical -> high -> medium -> low -> info).
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Sorted list
    """
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }
    
    return sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "info").lower(), 999)
    )


def count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count findings by severity level.
    
    Returns:
        Dictionary with severity counts: {"critical": 2, "high": 5, ...}
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in counts:
            counts[severity] += 1
    
    return counts


# ============================================================================
# VALIDATION
# ============================================================================

def validate_port(port: str | int) -> bool:
    """
    Check if port number is valid (1-65535).
    
    Examples:
        validate_port(80) -> True
        validate_port("443") -> True
        validate_port(70000) -> False
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_severity(severity: str) -> bool:
    """
    Check if severity is valid.
    
    Examples:
        validate_severity("high") -> True
        validate_severity("CRITICAL") -> True
        validate_severity("invalid") -> False
    """
    valid = {"critical", "high", "medium", "low", "info"}
    return severity.lower() in valid


# ============================================================================
# MISC
# ============================================================================

def chunks(lst: List[Any], n: int) -> List[List[Any]]:
    """
    Split list into chunks of size n.
    
    Examples:
        chunks([1,2,3,4,5], 2) -> [[1,2], [3,4], [5]]
    """
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def flatten_list(nested: List[List[Any]]) -> List[Any]:
    """
    Flatten a list of lists.
    
    Examples:
        flatten_list([[1,2], [3,4]]) -> [1,2,3,4]
    """
    return [item for sublist in nested for item in sublist]
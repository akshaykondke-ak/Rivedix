"""
Httpx module for HTTP probing and technology detection.
"""

import json
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class HttpxModule(BinaryModule):
    """
    HTTP probing tool with technology detection.
    
    Features:
        - URL discovery
        - Status code checking
        - Title extraction
        - Technology stack detection
        - Redirect following
    """
    
    name = "httpx"
    description = "Fast HTTP probing with technology detection"
    version = "1.2"
    required_binary = "httpx"

    def run(self, target: str) -> str:
        """
        Execute httpx on target.
        
        Args:
            target: Target URL or hostname
            
        Returns:
            JSON output from httpx
        """
        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            # Try HTTPS first (more common)
            target = f"https://{target}"
        
        # Build command
        args = [
            self.binary_path,
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-json",
            target
        ]
        
        self._log_info(f"Probing: {target}")
        
        # Execute
        timeout = self._get_timeout()
        result = self._run_command(args, timeout=timeout)
        
        if result.timed_out:
            self._log_error(f"Httpx timed out after {timeout}s")
            raise TimeoutError(f"Httpx exceeded {timeout}s timeout")
        
        if not result.success and not result.has_output():
            self._log_warning(f"Httpx failed: {result.stderr}")
            # Don't raise - httpx may fail for unreachable hosts
        
        # Store output
        self.raw_output = result.stdout
        
        self._log_debug(f"Httpx produced {len(self.raw_output)} bytes")
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """
        Parse httpx JSON output.
        
        Returns:
            List of findings with HTTP information
        """
        findings = []
        output = (self.raw_output or "").strip()
        
        if not output:
            self._log_warning("No output to parse")
            self._add_finding(
                title="No HTTP Response",
                description="Target did not respond to HTTP probes",
                severity="info",
                evidence="No output from httpx"
            )
            return self.findings
        
        # Parse JSON lines
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
                finding = self._parse_http_response(item)
                if finding:
                    findings.append(finding)
            
            except json.JSONDecodeError as e:
                self._log_warning(f"Failed to parse JSON line: {e}")
                continue
            
            except Exception as e:
                self._log_error(f"Error parsing response: {e}", exc_info=True)
                continue
        
        if not findings:
            self._log_warning("No valid HTTP responses parsed")
            self._add_finding(
                title="HTTP Probe Failed",
                description="Could not parse any valid HTTP responses",
                severity="info",
                evidence=output[:500]
            )
        
        self.findings = findings
        return findings

    def _parse_http_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single httpx JSON response.
        
        Args:
            data: Parsed JSON object from httpx
            
        Returns:
            Finding dictionary
        """
        # Extract fields
        url = data.get("url") or data.get("input") or "unknown"
        status_code = data.get("status_code", "unknown")
        title = data.get("title", "No title")
        content_length = data.get("content_length", 0)
        
        # Technology detection
        tech = data.get("tech", [])
        if isinstance(tech, list):
            tech_str = ", ".join(tech) if tech else "None detected"
        else:
            tech_str = str(tech)
        
        # Server header
        server = data.get("webserver") or data.get("server", "Unknown")
        
        # Build description
        desc_parts = [f"HTTP {status_code}"]
        if title and title != "No title":
            desc_parts.append(f"| {title}")
        
        description = " ".join(desc_parts)
        
        # Build evidence
        evidence_parts = [
            f"URL: {url}",
            f"Status: {status_code}",
            f"Server: {server}",
            f"Content-Length: {content_length}",
            f"Technologies: {tech_str}"
        ]
        
        evidence = "\n".join(evidence_parts)
        
        # Assess severity based on status code
        severity = self._assess_http_severity(status_code, tech)
        
        return {
            "title": url,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            # Structured data
            "url": url,
            "status_code": status_code,
            "title_text": title,
            "server": server,
            "technologies": tech,
            "content_length": content_length,
            "raw_json": json.dumps(data, indent=2)
        }

    def _assess_http_severity(
        self,
        status_code: int | str,
        technologies: List[str]
    ) -> str:
        """
        Assess severity based on HTTP response.
        
        Args:
            status_code: HTTP status code
            technologies: Detected technologies
            
        Returns:
            Severity level
        """
        try:
            code = int(status_code)
        except (ValueError, TypeError):
            return "info"
        
        # Server errors might indicate issues
        if 500 <= code < 600:
            return "low"
        
        # Check for outdated technologies
        outdated_tech = {
            "PHP/5", "Apache/2.2", "IIS/6", "IIS/7",
            "jQuery 1.", "AngularJS 1."
        }
        
        if technologies:
            for tech in technologies:
                if any(old in str(tech) for old in outdated_tech):
                    return "low"
        
        # Default
        return "info"








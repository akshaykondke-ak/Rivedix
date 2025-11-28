"""
Nmap module with multiple scan profiles and robust XML parsing.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class NmapModule(BinaryModule):
    """
    Nmap port scanner with multiple scan profiles.
    
    Scan Types:
        - short: Top 100 ports, fast
        - fast: Fast scan, limited ports
        - deep: Full port scan with service detection
        - discovery: Host discovery only (no port scan)
        - firewall-bypass: ACK scan to detect firewalls
        - slow: Slow comprehensive scan
    """
    
    name = "nmap"
    description = "Network port scanner with service detection"
    version = "1.3"
    required_binary = "nmap"
    
    # Scan profile definitions
    PROFILES = {
        "short": "-T3 -Pn -sV --top-ports 100 -oX -",
        "fast": "-T4 -Pn -F -oX -",
        "deep": "-T2 -A -p- -oX -",
        "discovery": "-sn -oX -",
        "firewall-bypass": "-Pn -sA -T3 -oX -",
        "slow": "-T1 -sV -p- -oX -",
        "default": "-T3 -Pn -sV --top-ports 100 -oX -"
    }

    def _get_scan_args(self) -> str:
        """
        Get scan arguments based on selected profile.
        
        Priority:
            1. Instance attribute (set by Runner)
            2. Config file setting
            3. Default profile
        """
        # Try runner-provided scan type
        scan_type = getattr(self, "selected_scan_type", None)
        
        # Try config setting
        if not scan_type and self.config:
            scan_type = (
                getattr(self.config, "type", None) or 
                getattr(self.config, "scan_type", None)
            )
        
        # Fallback to default
        scan_type = (scan_type or "default").lower()
        
        args = self.PROFILES.get(scan_type, self.PROFILES["default"])
        
        self._log_info(f"Using scan profile: {scan_type}")
        return args

    def run(self, target: str) -> str:
        """
        Execute nmap scan on target.
        
        Args:
            target: Target IP, hostname, or CIDR range
            
        Returns:
            Raw XML output from nmap
        """
        args = self._get_scan_args()
        
        # Build command (nmap args target)
        cmd = f"{self.binary_path} {args} {target}"
        
        self._log_info(f"Executing: nmap {args} {target}")
        
        # Execute with timeout
        timeout = self._get_timeout()
        result = self._run_command(cmd, timeout=timeout, shell=True)
        
        if not result.success:
            self._log_warning(f"Nmap returned non-zero exit code: {result.returncode}")
            # Nmap can return 1 for some valid scans, so we don't fail here
        
        if result.timed_out:
            self._log_error(f"Nmap scan timed out after {timeout}s")
            raise TimeoutError(f"Nmap scan exceeded {timeout}s timeout")
        
        # Store raw output
        self.raw_output = result.get_combined_output()
        
        self._log_debug(f"Nmap produced {len(self.raw_output)} bytes of output")
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output into findings.
        
        Returns:
            List of findings with port/service information
        """
        findings = []
        output = (self.raw_output or "").strip()
        
        if not output:
            self._log_warning("No output to parse")
            return findings
        
        # Check if output is XML
        if not ("<?xml" in output or "<nmaprun" in output):
            self._log_warning("Output is not XML format")
            # Return raw output as single finding
            self._add_finding(
                title="Nmap Non-XML Output",
                description="Nmap returned text output instead of XML",
                severity="info",
                evidence=output[:2000]
            )
            return self.findings
        
        try:
            # Parse XML
            root = ET.fromstring(output)
            
            # Extract scan metadata
            scan_args = root.get("args", "")
            start_time = root.get("start", "")
            
            self._log_debug(f"Parsing XML from scan: {scan_args}")
            
            # Parse each host
            for host in root.findall("host"):
                host_findings = self._parse_host(host)
                findings.extend(host_findings)
            
            # If no findings, add summary
            if not findings:
                self._add_finding(
                    title="Nmap Scan Complete",
                    description="Scan completed but no open ports found",
                    severity="info",
                    evidence=f"Scan args: {scan_args}"
                )
        
        except ET.ParseError as e:
            self._log_error(f"XML parsing failed: {e}", exc_info=True)
            # Return error as finding
            self._add_finding(
                title="Nmap XML Parse Error",
                description=f"Failed to parse XML output: {e}",
                severity="info",
                evidence=output[:2000]
            )
        
        except Exception as e:
            self._log_error(f"Unexpected parsing error: {e}", exc_info=True)
            self._add_finding(
                title="Nmap Parsing Error",
                description=f"Unexpected error during parsing: {e}",
                severity="info",
                evidence=output[:2000]
            )
        
        self.findings = findings
        return findings

    def _parse_host(self, host_element: ET.Element) -> List[Dict[str, Any]]:
        """
        Parse a single host element from nmap XML.
        
        Args:
            host_element: XML element for host
            
        Returns:
            List of findings for this host
        """
        findings = []
        
        # Get host address
        address_elem = host_element.find("address")
        ip_addr = address_elem.get("addr") if address_elem is not None else "unknown"
        
        # Get hostname if available
        hostnames = host_element.find("hostnames")
        hostname = None
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")
        
        # Parse ports
        ports_elem = host_element.find("ports")
        if ports_elem is None:
            return findings
        
        for port_elem in ports_elem.findall("port"):
            port_finding = self._parse_port(port_elem, ip_addr, hostname)
            if port_finding:
                findings.append(port_finding)
        
        return findings

    def _parse_port(
        self,
        port_elem: ET.Element,
        ip_addr: str,
        hostname: str = None
    ) -> Dict[str, Any]:
        """
        Parse a single port element.
        
        Args:
            port_elem: XML element for port
            ip_addr: Host IP address
            hostname: Host hostname (optional)
            
        Returns:
            Finding dictionary or None
        """
        # Port info
        port_id = port_elem.get("portid", "unknown")
        protocol = port_elem.get("protocol", "tcp")
        
        # State
        state_elem = port_elem.find("state")
        state = state_elem.get("state") if state_elem is not None else "unknown"
        
        # Service info
        service_elem = port_elem.find("service")
        service_name = "unknown"
        service_product = None
        service_version = None
        
        if service_elem is not None:
            service_name = service_elem.get("name", "unknown")
            service_product = service_elem.get("product")
            service_version = service_elem.get("version")
        
        # Build description
        desc_parts = [f"{service_name}"]
        if service_product:
            desc_parts.append(service_product)
        if service_version:
            desc_parts.append(f"v{service_version}")
        
        description = " ".join(desc_parts)
        
        # Build evidence
        evidence_parts = [f"{ip_addr}:{port_id}"]
        if hostname:
            evidence_parts.append(f"({hostname})")
        evidence_parts.append(f"- {service_name}")
        
        evidence = " ".join(evidence_parts)
        
        # Determine severity based on port and service
        severity = self._assess_severity(port_id, service_name, state)
        
        # Build title
        if state == "open":
            title = f"Open Port {port_id}/{protocol}"
        else:
            title = f"Port {port_id}/{protocol} ({state})"
        
        return {
            "title": title,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            # Additional structured data
            "port": port_id,
            "protocol": protocol,
            "state": state,
            "service": service_name,
            "product": service_product,
            "version": service_version,
            "ip": ip_addr,
            "hostname": hostname
        }

    def _assess_severity(self, port: str, service: str, state: str) -> str:
        """
        Assess severity based on port, service, and state.
        
        Rules:
            - Closed/filtered ports: info
            - Common risky services (RDP, MySQL, etc.): medium
            - Privileged ports (<1024): low
            - High ports: info
        """
        if state != "open":
            return "info"
        
        try:
            port_num = int(port)
        except ValueError:
            return "info"
        
        # High-risk services
        risky_services = {
            "rdp", "mysql", "mssql", "postgresql", "mongodb",
            "redis", "elasticsearch", "telnet", "ftp", "vnc"
        }
        
        if service.lower() in risky_services:
            return "medium"
        
        # Privileged ports
        if port_num < 1024:
            return "low"
        
        # Default
        return "info"


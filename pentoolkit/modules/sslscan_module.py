"""
Remaining pentoolkit modules refactored with error handling.
Copy each class to its respective file:
- sslscan_module.py -> OpenSSLTLSModule
- subfinder_module.py -> SubfinderModule
- whatweb_module.py -> WhatWebModule
"""

# ============================================================================
# pentoolkit/modules/sslscan_module.py
# ============================================================================

import re
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class OpenSSLTLSModule(BinaryModule):
    """
    TLS/SSL analysis using OpenSSL.
    
    Features:
        - Protocol version detection (TLS 1.0-1.3)
        - Certificate information extraction
        - Cipher suite enumeration
    """
    
    name = "tlsinfo"
    description = "TLS/SSL certificate and protocol analyzer"
    version = "1.3"
    required_binary = "openssl"

    def run(self, target: str) -> str:
        """
        Execute OpenSSL TLS analysis.
        
        Args:
            target: Target hostname
            
        Returns:
            Raw openssl output
        """
        # Remove scheme if present
        target = target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0]  # Remove path
        
        self._log_info(f"Analyzing TLS for: {target}")
        
        # Test multiple TLS versions
        supported_protocols = []
        outputs = []
        
        protocol_flags = [
            ("-tls1_3", "TLS 1.3"),
            ("-tls1_2", "TLS 1.2"),
            ("-tls1_1", "TLS 1.1"),
            ("-tls1", "TLS 1.0")
        ]
        
        for flag, version_name in protocol_flags:
            cmd = [
                self.binary_path,
                "s_client",
                "-connect", f"{target}:443",
                "-servername", target,
                flag
            ]
            
            try:
                result = self._run_command(
                    cmd,
                    timeout=10,
                    stdin="",  # Send empty stdin
                    check_returncode=False
                )
                
                output = result.get_combined_output()
                
                # Check if connection succeeded
                if "BEGIN CERTIFICATE" in output or "Verify return code" in output:
                    supported_protocols.append(version_name)
                    outputs.append(output)
                    self._log_debug(f"Supported: {version_name}")
            
            except Exception as e:
                self._log_debug(f"Protocol {version_name} test failed: {e}")
                continue
        
        # Store supported protocols for parsing
        self.supported_protocols = supported_protocols
        
        # Use first successful output or try default connection
        if outputs:
            self.raw_output = outputs[0]
        else:
            # Try default connection
            cmd = [
                self.binary_path,
                "s_client",
                "-connect", f"{target}:443",
                "-servername", target
            ]
            result = self._run_command(cmd, timeout=10, stdin="", check_returncode=False)
            self.raw_output = result.get_combined_output()
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """Parse OpenSSL output for TLS information."""
        findings = []
        output = self.raw_output or ""
        
        # Supported protocols
        protocols = getattr(self, "supported_protocols", [])
        
        if protocols:
            self._add_finding(
                title="Supported TLS Protocols",
                description=", ".join(protocols),
                severity=self._assess_protocol_severity(protocols),
                evidence=", ".join(protocols)
            )
        
        # Extract certificate
        cert_match = re.search(
            r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
            output,
            re.DOTALL
        )
        
        if cert_match:
            cert_pem = cert_match.group(0)
            cert_info = self._parse_certificate(cert_pem)
            
            if cert_info:
                findings.append(cert_info)
        
        self.findings = findings
        return findings

    def _parse_certificate(self, pem: str) -> Dict[str, Any]:
        """Parse certificate using openssl x509."""
        try:
            # Write PEM to temp file and parse
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(pem)
                temp_path = f.name
            
            try:
                cmd = [
                    self.binary_path,
                    "x509",
                    "-in", temp_path,
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-dates",
                    "-ext", "subjectAltName"
                ]
                
                result = self._run_command(cmd, timeout=5, check_returncode=False)
                cert_text = result.stdout
                
                # Parse fields
                issuer = re.search(r"issuer=(.+)", cert_text)
                subject = re.search(r"subject=(.+)", cert_text)
                not_after = re.search(r"notAfter=(.+)", cert_text)
                
                description_parts = []
                if issuer:
                    description_parts.append(f"Issuer: {issuer.group(1)}")
                if subject:
                    description_parts.append(f"Subject: {subject.group(1)}")
                if not_after:
                    description_parts.append(f"Expires: {not_after.group(1)}")
                
                return {
                    "title": "TLS Certificate Information",
                    "description": "\n".join(description_parts),
                    "severity": "info",
                    "evidence": cert_text
                }
            
            finally:
                os.unlink(temp_path)
        
        except Exception as e:
            self._log_error(f"Certificate parsing failed: {e}")
            return {
                "title": "TLS Certificate",
                "description": "Certificate found but parsing failed",
                "severity": "info",
                "evidence": pem[:500]
            }

    def _assess_protocol_severity(self, protocols: List[str]) -> str:
        """Assess severity based on supported protocols."""
        # Check for outdated protocols
        if "TLS 1.0" in protocols:
            return "medium"
        if "TLS 1.1" in protocols:
            return "low"
        return "info"



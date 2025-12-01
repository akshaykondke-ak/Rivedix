

# """
# TLS/SSL analysis module - FIXED VERSION
# Properly detects only actually supported protocols.
# """

import re
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class OpenSSLTLSModule(BinaryModule):
    """
    TLS/SSL analysis using OpenSSL.
    
    FIXES:
    - ✅ Only reports ACTUALLY supported protocols
    - ✅ Tests each protocol version separately
    - ✅ Always returns self.findings
    """
    
    name = "tlsinfo"
    description = "TLS/SSL certificate and protocol analyzer"
    version = "1.4"
    required_binary = "openssl"

    def run(self, target: str) -> str:
        """Execute OpenSSL TLS analysis."""
        # Clean target
        target = target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0]
        
        self._log_info(f"Analyzing TLS for: {target}")
        
        # ✅ FIX: Test each protocol separately and check if connection succeeds
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
                    stdin="",
                    check_returncode=False
                )
                
                output = result.get_combined_output()
                
                # ✅ CRITICAL: Check if handshake actually succeeded
                # Look for success indicators, NOT just certificate presence
                if self._is_protocol_supported(output):
                    supported_protocols.append(version_name)
                    outputs.append(output)
                    self._log_debug(f"✓ Supported: {version_name}")
                else:
                    self._log_debug(f"✗ Not supported: {version_name}")
            
            except Exception as e:
                self._log_debug(f"Protocol {version_name} test failed: {e}")
                continue
        
        # Store supported protocols
        self.supported_protocols = supported_protocols
        
        # Use first successful output
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

    def _is_protocol_supported(self, output: str) -> bool:
        """
        Check if protocol handshake succeeded.
        
        ✅ CRITICAL FIX: Properly detect successful TLS connection
        """
        # HARD FAILURE indicators (connection definitely failed)
        hard_failures = [
            "no peer certificate available",
            "ssl handshake failure",
            "sslv3 alert handshake failure",
            "no protocols available",
            "wrong version number",
            "Connection refused",
            "connect: Connection refused",
            "errno"
        ]
        
        # Check for hard failures first
        if any(fail in output for fail in hard_failures):
            return False
        
        # SUCCESS indicators (connection definitely succeeded)
        success_indicators = [
            "Cipher is ",  # Shows negotiated cipher (e.g., "Cipher is TLS_AES_256_GCM_SHA384")
            "Protocol: TLS",  # Shows protocol version
            "New, TLS",  # TLS handshake completed
            "Verify return code: 0 (ok)"  # Successful verification
        ]
        
        # Must have at least TWO success indicators
        success_count = sum(1 for indicator in success_indicators if indicator in output)
        
        return success_count >= 2

    def parse_output(self) -> List[Dict[str, Any]]:
        """Parse OpenSSL output for TLS information."""
        output = self.raw_output or ""
        
        # ✅ FIX: Get ONLY actually supported protocols
        protocols = getattr(self, "supported_protocols", [])
        
        if protocols:
            self._add_finding(
                title="Supported TLS Protocols",
                description=", ".join(protocols),
                severity=self._assess_protocol_severity(protocols),
                evidence=", ".join(protocols)
            )
        else:
            self._add_finding(
                title="TLS Connection Failed",
                description="Could not establish TLS connection to port 443",
                severity="info",
                evidence=output[:500]
            )
            return self.findings  # ✅ Return early
        
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
                self._add_finding(**cert_info)
        
        return self.findings  # ✅ CRITICAL FIX: Always return findings!

    def _parse_certificate(self, pem: str) -> Dict[str, Any]:
        """Parse certificate using openssl x509."""
        try:
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
        # TLS 1.0 and 1.1 are deprecated
        if "TLS 1.0" in protocols:
            return "medium"  # TLS 1.0 is deprecated
        if "TLS 1.1" in protocols:
            return "low"  # TLS 1.1 is deprecated
        return "info"  # TLS 1.2+ is good




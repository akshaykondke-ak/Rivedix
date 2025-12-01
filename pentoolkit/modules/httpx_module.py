



"""
Httpx module - ENHANCED VERSION
Properly exposes tech stack for report visualization.
"""

# import json
# from typing import List, Dict, Any, Set
# from pentoolkit.modules.base import BinaryModule


# class HttpxModule(BinaryModule):
#     """
#     HTTP probing tool with technology detection.
    
#     ENHANCEMENTS:
#     - ✅ Tech stack exposed in findings
#     - ✅ Better deduplication
#     - ✅ Status code analysis
#     """
    
#     name = "httpx"
#     description = "HTTP probing with tech stack detection"
#     version = "1.5"
#     required_binary = "httpx"

#     def run(self, target: str) -> str:
#         """Execute httpx with comprehensive detection."""
#         # Clean target
#         clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
#         # Build command
#         args = [
#             self.binary_path,
#             "-u", clean_target,
#             "-silent",
#             "-follow-redirects",
#             "-status-code",
#             "-title",
#             "-tech-detect",
#             "-server",
#             "-json",
#             "-timeout", "10",
#             "-retries", "1"
#         ]
        
#         self._log_info(f"Probing: {clean_target}")
        
#         # Execute
#         timeout = self._get_timeout()
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_error(f"Httpx timed out after {timeout}s")
#             raise TimeoutError(f"Httpx exceeded {timeout}s timeout")
        
#         self.raw_output = result.stdout
        
#         if not result.success:
#             self._log_debug(f"Httpx exit code {result.returncode}")
        
#         self._log_debug(f"Httpx produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """Parse httpx JSON with tech stack extraction."""
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             self._log_warning("No HTTP/HTTPS response from target")
#             self._add_finding(
#                 title="No HTTP/HTTPS Response",
#                 description="Target did not respond to HTTP or HTTPS probes",
#                 severity="info",
#                 evidence="No output from httpx"
#             )
#             return self.findings
        
#         # Deduplicate by URL
#         seen_urls: Set[str] = set()
        
#         for line in output.splitlines():
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 url = item.get("url") or item.get("input") or ""
                
#                 # Deduplicate
#                 if url and url not in seen_urls:
#                     seen_urls.add(url)
#                     finding = self._parse_http_response(item)
#                     if finding:
#                         self._add_finding(**finding)
            
#             except json.JSONDecodeError as e:
#                 self._log_warning(f"Failed to parse JSON line: {e}")
#                 continue
#             except Exception as e:
#                 self._log_error(f"Error parsing response: {e}")
#                 continue
        
#         if not self.findings:
#             self._log_warning("Httpx ran but no valid responses")
#             self._add_finding(
#                 title="HTTP Probe Failed",
#                 description="Httpx could not parse valid responses",
#                 severity="info",
#                 evidence=output[:500]
#             )
        
#         return self.findings

#     def _parse_http_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Parse HTTP response with FULL tech stack exposure.
        
#         ✅ ENHANCEMENT: Tech stack exposed for report visualization
#         """
#         # Extract fields
#         url = data.get("url") or data.get("input") or "unknown"
#         status_code = data.get("status_code", 0)
#         title = data.get("title", "")
#         content_length = data.get("content_length", 0)
        
#         # ✅ CRITICAL: Extract tech stack as list
#         tech = data.get("tech", [])
#         tech_list = tech if isinstance(tech, list) else [tech] if tech else []
#         tech_str = ", ".join(str(t) for t in tech_list) if tech_list else "None detected"
        
#         # Server
#         server = data.get("webserver") or data.get("server", "Unknown")
        
#         # Build description
#         desc_parts = [f"HTTP {status_code}"]
#         if title:
#             desc_parts.append(f"| {title[:50]}")
#         if server != "Unknown":
#             desc_parts.append(f"| {server}")
        
#         description = " ".join(desc_parts)
        
#         # Build evidence
#         evidence_parts = [
#             f"URL: {url}",
#             f"Status: {status_code}",
#             f"Server: {server}",
#             f"Content-Length: {content_length}",
#             f"Technologies: {tech_str}"
#         ]
        
#         evidence = "\n".join(evidence_parts)
        
#         # Assess severity
#         severity = "info"
#         try:
#             code = int(status_code)
#             if 500 <= code < 600:
#                 severity = "low"
#         except (ValueError, TypeError):
#             pass
        
#         # ✅ CRITICAL: Return tech_list for report visualization
#         return {
#             "title": url,
#             "description": description,
#             "severity": severity,
#             "evidence": evidence,
#             "technologies": tech_list,  # ✅ Exposed for report
#             "status_code": status_code,
#             "server": server,
#             "url": url
#         }






# """
# Subfinder module - FIXED VERSION
# Properly returns findings and counts subdomains.
# """

# import json
# from typing import List, Dict, Any
# from pentoolkit.modules.base import BinaryModule


# class SubfinderModule(BinaryModule):
#     """
#     Subdomain enumeration using Subfinder.
    
#     FIXES:
#     - ✅ Always returns self.findings
#     - ✅ Proper subdomain counting
#     - ✅ Handles both JSON and plain text
#     """
    
#     name = "subfinder"
#     description = "Passive subdomain enumeration tool"
#     version = "1.2"
#     required_binary = "subfinder"

#     def run(self, target: str) -> str:
#         """Execute subfinder on domain."""
#         # Extract domain from URL if needed
#         from pentoolkit.utils.helpers import extract_domain_from_url
        
#         if target.startswith("http"):
#             domain = extract_domain_from_url(target)
#         else:
#             domain = target.split("/")[0]
        
#         self._log_info(f"Enumerating subdomains for: {domain}")
        
#         # Build command
#         args = [
#             self.binary_path,
#             "-d", domain,
#             "-silent",
#             "-json"
#         ]
        
#         # Execute
#         timeout = self._get_timeout()
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_warning(f"Subfinder timed out after {timeout}s")
        
#         self.raw_output = result.stdout
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """
#         Parse subfinder JSON output.
        
#         ✅ FIXED: Now properly returns self.findings!
#         """
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             self._log_info("No subdomains found")
#             self._add_finding(
#                 title="No Subdomains Discovered",
#                 description="Subfinder did not find any subdomains",
#                 severity="info",
#                 evidence="Empty result"
#             )
#             return self.findings  # ✅ CRITICAL FIX
        
#         # Parse JSON lines
#         subdomains = []
        
#         for line in output.splitlines():
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 subdomain = item.get("host") or item.get("domain") or str(item)
#                 if subdomain and subdomain not in subdomains:
#                     subdomains.append(subdomain)
            
#             except json.JSONDecodeError:
#                 # Might be plain text
#                 if line and line not in subdomains:
#                     subdomains.append(line)
        
#         # ✅ CRITICAL: Always create finding even with 1 subdomain
#         if subdomains:
#             self._log_info(f"Found {len(subdomains)} subdomain(s)")
            
#             # Add summary finding with FULL subdomain list
#             self._add_finding(
#                 title=f"Discovered {len(subdomains)} Subdomain(s)",
#                 description=f"Found {len(subdomains)} unique subdomain(s) via passive enumeration",
#                 severity="info",
#                 evidence="\n".join(subdomains),  # All subdomains in evidence
#                 subdomain_count=len(subdomains),  # ✅ For report stats
#                 subdomains=subdomains  # ✅ For report table
#             )
#         else:
#             # No subdomains parsed
#             self._add_finding(
#                 title="No Subdomains Discovered",
#                 description="Subfinder executed but found no subdomains",
#                 severity="info",
#                 evidence="No subdomains found"
#             )
        
#         return self.findings  # ✅ CRITICAL FIX: Always return findings!







# """
# Httpx module - COMPLETE WORKING VERSION
# """

# import json
# from typing import List, Dict, Any, Set
# from pentoolkit.modules.base import BinaryModule


# class HttpxModule(BinaryModule):
#     """HTTP probing with tech stack detection."""
    
#     name = "httpx"
#     description = "HTTP probing with tech stack detection"
#     version = "1.5"
#     required_binary = "httpx"

#     def run(self, target: str) -> str:
#         """Execute httpx."""
#         clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
#         args = [
#             self.binary_path,
#             "-u", clean_target,
#             "-silent",
#             "-follow-redirects",
#             "-status-code",
#             "-title",
#             "-tech-detect",
#             "-server",
#             "-json",
#             "-timeout", "10",
#             "-retries", "1"
#         ]
        
#         self._log_info(f"Probing: {clean_target}")
        
#         timeout = self._get_timeout()
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_error(f"Httpx timed out after {timeout}s")
#             raise TimeoutError(f"Httpx exceeded {timeout}s timeout")
        
#         self.raw_output = result.stdout
        
#         if not result.success:
#             self._log_debug(f"Httpx exit code {result.returncode}")
        
#         self._log_debug(f"Httpx produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """Parse httpx JSON."""
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             self._log_warning("No HTTP/HTTPS response")
#             self._add_finding(
#                 title="No HTTP/HTTPS Response",
#                 description="Target did not respond to HTTP or HTTPS probes",
#                 severity="info",
#                 evidence="No output from httpx"
#             )
#             return self.findings
        
#         seen_urls: Set[str] = set()
        
#         for line in output.splitlines():
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 url = item.get("url") or item.get("input") or ""
                
#                 if url and url not in seen_urls:
#                     seen_urls.add(url)
                    
#                     # Extract data
#                     status_code = item.get("status_code", 0)
#                     title = item.get("title", "")
#                     server = item.get("webserver") or item.get("server", "Unknown")
#                     content_length = item.get("content_length", 0)
                    
#                     # ✅ CRITICAL: Extract tech stack
#                     tech = item.get("tech", [])
#                     tech_list = tech if isinstance(tech, list) else [tech] if tech else []
#                     tech_str = ", ".join(str(t) for t in tech_list) if tech_list else "None detected"
                    
#                     # Build description
#                     desc_parts = [f"HTTP {status_code}"]
#                     if title:
#                         desc_parts.append(f"| {title[:50]}")
#                     if server != "Unknown":
#                         desc_parts.append(f"| {server}")
                    
#                     description = " ".join(desc_parts)
                    
#                     # Build evidence
#                     evidence_parts = [
#                         f"URL: {url}",
#                         f"Status: {status_code}",
#                         f"Server: {server}",
#                         f"Content-Length: {content_length}",
#                         f"Technologies: {tech_str}"
#                     ]
                    
#                     evidence = "\n".join(evidence_parts)
                    
#                     # Assess severity
#                     severity = "info"
#                     try:
#                         code = int(status_code)
#                         if 500 <= code < 600:
#                             severity = "low"
#                     except (ValueError, TypeError):
#                         pass
                    
#                     # ✅ CREATE FINDING with technologies field
#                     self._add_finding(
#                         title=url,
#                         description=description,
#                         severity=severity,
#                         evidence=evidence,
#                         technologies=tech_list,  # ✅ For report tech stack card
#                         status_code=status_code,
#                         server=server,
#                         url=url
#                     )
            
#             except json.JSONDecodeError as e:
#                 self._log_warning(f"Failed to parse JSON: {e}")
#                 continue
#             except Exception as e:
#                 self._log_error(f"Error parsing response: {e}")
#                 continue
        
#         if not self.findings:
#             self._log_warning("Httpx ran but no valid responses")
#             self._add_finding(
#                 title="HTTP Probe Failed",
#                 description="Could not parse valid responses",
#                 severity="info",
#                 evidence=output[:500]
#             )
        
#         return self.findings










# """
# Httpx module for HTTP probing - WORKING FIXED VERSION.
# """

# import json
# from typing import List, Dict, Any, Set
# from pentoolkit.modules.base import BinaryModule


# class HttpxModule(BinaryModule):
#     """
#     HTTP probing tool with technology detection.
    
#     FIXES:
#     - Removed indentation errors
#     - Simplified tech detection
#     - Better error handling
#     """
    
#     name = "httpx"
#     description = "HTTP probing with tech stack detection"
#     version = "1.4"
#     required_binary = "httpx"

#     def run(self, target: str) -> str:
#         """Execute httpx with comprehensive detection."""
#         # Clean target
#         clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
#         # Build command
#         args = [
#             self.binary_path,
#             "-u", clean_target,
#             "-silent",
#             "-follow-redirects",
#             "-status-code",
#             "-title",
#             "-tech-detect",
#             "-server",
#             "-json",
#             "-timeout", "10",
#             "-retries", "1"
#         ]
        
#         self._log_info(f"Probing: {clean_target}")
        
#         # Execute
#         timeout = self._get_timeout()
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_error(f"Httpx timed out after {timeout}s")
#             raise TimeoutError(f"Httpx exceeded {timeout}s timeout")
        
#         # Store output
#         self.raw_output = result.stdout
        
#         if not result.success:
#             self._log_debug(f"Httpx exit code {result.returncode}")
        
#         self._log_debug(f"Httpx produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """Parse httpx JSON with deduplication."""
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             self._log_warning("No HTTP/HTTPS response from target")
#             self._add_finding(
#                 title="No HTTP/HTTPS Response",
#                 description="Target did not respond to HTTP or HTTPS probes",
#                 severity="info",
#                 evidence="No output from httpx"
#             )
#             return self.findings
        
#         # Deduplicate by URL
#         seen_urls: Set[str] = set()
        
#         for line in output.splitlines():
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 url = item.get("url") or item.get("input") or ""
                
#                 # Deduplicate
#                 if url and url not in seen_urls:
#                     seen_urls.add(url)
#                     finding = self._parse_http_response(item)
#                     if finding:
#                         self._add_finding(**finding)
            
#             except json.JSONDecodeError as e:
#                 self._log_warning(f"Failed to parse JSON line: {e}")
#                 continue
#             except Exception as e:
#                 self._log_error(f"Error parsing response: {e}", exc_info=True)
#                 continue
        
#         if not self.findings:
#             self._log_warning("Httpx ran but no valid responses")
#             self._add_finding(
#                 title="HTTP Probe Failed",
#                 description="Httpx could not parse valid responses",
#                 severity="info",
#                 evidence=output[:500]
#             )
        
#         return self.findings

#     def _parse_http_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """Parse HTTP response."""
#         # Extract fields
#         url = data.get("url") or data.get("input") or "unknown"
#         status_code = data.get("status_code", 0)
#         title = data.get("title", "")
#         content_length = data.get("content_length", 0)
        
#         # Tech detection
#         tech = data.get("tech", [])
#         tech_list = tech if isinstance(tech, list) else [tech] if tech else []
#         tech_str = ", ".join(str(t) for t in tech_list) if tech_list else "None detected"
        
#         # Server
#         server = data.get("webserver") or data.get("server", "Unknown")
        
#         # Build description
#         desc_parts = [f"HTTP {status_code}"]
#         if title:
#             desc_parts.append(f"| {title[:50]}")
#         if server != "Unknown":
#             desc_parts.append(f"| {server}")
        
#         description = " ".join(desc_parts)
        
#         # Build evidence
#         evidence_parts = [
#             f"URL: {url}",
#             f"Status: {status_code}",
#             f"Server: {server}",
#             f"Content-Length: {content_length}",
#             f"Technologies: {tech_str}"
#         ]
        
#         evidence = "\n".join(evidence_parts)
        
#         # Assess severity
#         severity = "info"
#         try:
#             code = int(status_code)
#             if 500 <= code < 600:
#                 severity = "low"
#         except (ValueError, TypeError):
#             pass
        
#         return {
#             "title": url,
#             "description": description,
#             "severity": severity,
#             "evidence": evidence
#         }











"""
Httpx module - ENHANCED VERSION
Properly exposes tech stack for report visualization.
"""

import json
from typing import List, Dict, Any, Set
from pentoolkit.modules.base import BinaryModule


class HttpxModule(BinaryModule):
    """
    HTTP probing tool with technology detection.
    
    ENHANCEMENTS:
    - ✅ Tech stack exposed in findings
    - ✅ Better deduplication
    - ✅ Status code analysis
    """
    
    name = "httpx"
    description = "HTTP probing with tech stack detection"
    version = "1.5"
    required_binary = "httpx"

    def run(self, target: str) -> str:
        """Execute httpx with comprehensive detection."""
        # Clean target
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Build command
        args = [
            self.binary_path,
            "-u", clean_target,
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-json",
            "-timeout", "10",
            "-retries", "1"
        ]
        
        self._log_info(f"Probing: {clean_target}")
        
        # Execute
        timeout = self._get_timeout()
        result = self._run_command(args, timeout=timeout)
        
        if result.timed_out:
            self._log_error(f"Httpx timed out after {timeout}s")
            raise TimeoutError(f"Httpx exceeded {timeout}s timeout")
        
        self.raw_output = result.stdout
        
        if not result.success:
            self._log_debug(f"Httpx exit code {result.returncode}")
        
        self._log_debug(f"Httpx produced {len(self.raw_output)} bytes")
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """Parse httpx JSON with tech stack extraction."""
        output = (self.raw_output or "").strip()
        
        if not output:
            self._log_warning("No HTTP/HTTPS response from target")
            self._add_finding(
                title="No HTTP/HTTPS Response",
                description="Target did not respond to HTTP or HTTPS probes",
                severity="info",
                evidence="No output from httpx"
            )
            return self.findings
        
        # Deduplicate by URL
        seen_urls: Set[str] = set()
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
                url = item.get("url") or item.get("input") or ""
                
                # Deduplicate
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    finding = self._parse_http_response(item)
                    if finding:
                        self._add_finding(**finding)
            
            except json.JSONDecodeError as e:
                self._log_warning(f"Failed to parse JSON line: {e}")
                continue
            except Exception as e:
                self._log_error(f"Error parsing response: {e}")
                continue
        
        if not self.findings:
            self._log_warning("Httpx ran but no valid responses")
            self._add_finding(
                title="HTTP Probe Failed",
                description="Httpx could not parse valid responses",
                severity="info",
                evidence=output[:500]
            )
        
        return self.findings

    def _parse_http_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse HTTP response with FULL tech stack exposure.
        
        ✅ ENHANCEMENT: Tech stack exposed for report visualization
        """
        # Extract fields
        url = data.get("url") or data.get("input") or "unknown"
        status_code = data.get("status_code", 0)
        title = data.get("title", "")
        content_length = data.get("content_length", 0)
        
        # ✅ CRITICAL: Extract tech stack as list
        tech = data.get("tech", [])
        tech_list = tech if isinstance(tech, list) else [tech] if tech else []
        tech_str = ", ".join(str(t) for t in tech_list) if tech_list else "None detected"
        
        # Server
        server = data.get("webserver") or data.get("server", "Unknown")
        
        # Build description
        desc_parts = [f"HTTP {status_code}"]
        if title:
            desc_parts.append(f"| {title[:50]}")
        if server != "Unknown":
            desc_parts.append(f"| {server}")
        
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
        
        # Assess severity
        severity = "info"
        try:
            code = int(status_code)
            if 500 <= code < 600:
                severity = "low"
        except (ValueError, TypeError):
            pass
        
        # ✅ CRITICAL: Return tech_list for report visualization
        return {
            "title": url,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            "technologies": tech_list,  # ✅ Exposed for report
            "status_code": status_code,
            "server": server,
            "url": url
        }
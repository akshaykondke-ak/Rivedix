# """
# Nuclei vulnerability scanner module - FIXED VERSION.
# Handles both JSON lines and empty output correctly.
# """

# import json
# from typing import List, Dict, Any
# from pentoolkit.modules.base import BinaryModule


# class NucleiModule(BinaryModule):
#     """
#     Nuclei vulnerability scanner with improved error handling.
    
#     FIXES:
#     - Handles empty output gracefully
#     - Better JSON parsing
#     - Improved severity mapping
#     - Template execution tracking
#     """
    
#     name = "nuclei"
#     description = "Template-based vulnerability scanner"
#     version = "1.3"
#     required_binary = "nuclei"

#     def run(self, target: str) -> str:
#         """
#         Execute nuclei on target with robust configuration.
#         """
#         # Ensure target has scheme
#         if not target.startswith(("http://", "https://")):
#             target = f"https://{target}"
        
#         # Build command with conservative settings
#         args = [
#             self.binary_path,
#             "-u", target,
#             "-silent",           # Suppress banner
#             "-nc",               # No color codes
#             "-json",             # JSON output
#             "-stats",            # Show statistics
#         ]
        
#         # Add templates root if configured
#         templates_root = self._get_config_value("templates_root")
#         if templates_root:
#             args.extend(["-t", templates_root])
#             self._log_info(f"Using templates from: {templates_root}")
#         else:
#             self._log_warning("No templates_root configured, using default templates")
        
#         # Add severity filter
#         severity = self._get_config_value("severity", "critical,high,medium,low,info")
#         args.extend(["-severity", severity])
        
#         # Rate limiting (prevent overwhelming target)
#         rate_limit = self._get_config_value("rate_limit", 150)  # Increased default
#         args.extend(["-rl", str(rate_limit)])
        
#         # Concurrency
#         concurrency = self._get_config_value("concurrency", 25)
#         args.extend(["-c", str(concurrency)])
        
#         # Retries
#         args.extend(["-retries", "1"])
        
#         # Timeout per template
#         template_timeout = self._get_config_value("template_timeout", 10)
#         args.extend(["-timeout", str(template_timeout)])
        
#         # Disable interactsh (can cause hangs)
#         args.append("-ni")
        
#         # Disable update check
#         args.append("-duc")
        
#         self._log_info(f"Scanning: {target} with nuclei")
#         self._log_debug(f"Command: {' '.join(args)}")
        
#         # Execute with extended timeout
#         timeout = self._get_config_value("timeout", 600)  # 10 minutes default
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_warning(f"Nuclei timed out after {timeout}s (partial results may exist)")
        
#         if not result.success:
#             # Nuclei returns non-zero if templates have issues, but may still produce results
#             self._log_debug(f"Nuclei exit code {result.returncode}: {result.stderr[:200]}")
        
#         # Store both stdout and stderr (stats are in stderr)
#         self.raw_output = result.stdout
#         self._nuclei_stats = result.stderr  # Save stats separately
        
#         self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """
#         Parse nuclei JSON output with robust error handling.
#         """
#         findings = []
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             # Check if we have stats in stderr
#             stats = getattr(self, '_nuclei_stats', '')
            
#             # Parse stats to see if templates actually ran
#             if "templates loaded" in stats.lower():
#                 self._log_info("Nuclei scan completed with no vulnerabilities found")
#                 self._add_finding(
#                     title="No Vulnerabilities Detected",
#                     description="Nuclei scan completed successfully but found no matching templates",
#                     severity="info",
#                     evidence=f"Nuclei executed but returned no matches.\n\nStats:\n{stats[:500]}"
#                 )
#             else:
#                 self._log_warning("Nuclei produced no output (may have failed to load templates)")
#                 self._add_finding(
#                     title="Nuclei Scan Failed",
#                     description="Nuclei did not execute successfully (check template path and configuration)",
#                     severity="info",
#                     evidence=stats[:500] if stats else "No output or stats available"
#                 )
            
#             return self.findings
        
#         # Parse JSON lines (nuclei outputs one JSON per finding)
#         vuln_count = 0
#         parse_errors = 0
        
#         for line_num, line in enumerate(output.splitlines(), 1):
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 finding = self._parse_nuclei_finding(item)
#                 if finding:
#                     findings.append(finding)
#                     vuln_count += 1
            
#             except json.JSONDecodeError as e:
#                 parse_errors += 1
#                 if parse_errors <= 3:  # Only log first 3 errors
#                     self._log_warning(f"Failed to parse JSON line {line_num}: {e}")
#                     self._log_debug(f"Problematic line: {line[:100]}")
#                 continue
            
#             except Exception as e:
#                 self._log_error(f"Error parsing finding at line {line_num}: {e}", exc_info=True)
#                 continue
        
#         if parse_errors > 0:
#             self._log_warning(f"Total JSON parse errors: {parse_errors}")
        
#         if vuln_count > 0:
#             self._log_info(f"Found {vuln_count} potential vulnerabilities")
#         elif not findings:
#             # If we had output but no findings parsed, something went wrong
#             self._add_finding(
#                 title="Nuclei Output Parse Error",
#                 description=f"Nuclei produced output but no valid findings could be parsed ({parse_errors} parse errors)",
#                 severity="info",
#                 evidence=output[:1000]
#             )
        
#         self.findings = findings
#         return findings

#     def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Parse a single nuclei JSON finding with enhanced data extraction.
#         """
#         # Extract info section
#         info = data.get("info", {})
        
#         # Template details
#         template_id = data.get("template-id") or data.get("templateID") or "unknown"
#         template_name = info.get("name", template_id)
        
#         # Severity (normalize)
#         severity = info.get("severity", "info").lower()
#         if severity not in {"critical", "high", "medium", "low", "info"}:
#             severity = "info"
        
#         # Description
#         description = info.get("description", "")
#         if not description:
#             description = f"Nuclei template match: {template_name}"
        
#         # Matched URL
#         matched_at = data.get("matched-at") or data.get("matched") or data.get("host", "")
#         host = data.get("host", "")
        
#         # Type of match
#         match_type = data.get("type", "")
        
#         # Matcher name (what triggered the match)
#         matcher_name = data.get("matcher-name", "")
        
#         # Extracted results (if any)
#         extracted = data.get("extracted-results", [])
        
#         # References
#         references = info.get("reference", [])
#         if isinstance(references, str):
#             references = [references]
        
#         # Filter out null/empty references
#         references = [r for r in references if r and r.lower() != "null"]
        
#         # Classification (CVE, CWE, etc.)
#         classification = info.get("classification", {})
#         cve_id = classification.get("cve-id", [])
#         cwe_id = classification.get("cwe-id", [])
        
#         # Normalize CVE/CWE (can be string or list)
#         if isinstance(cve_id, str):
#             cve_id = [cve_id] if cve_id and cve_id.lower() != "null" else []
#         if isinstance(cwe_id, str):
#             cwe_id = [cwe_id] if cwe_id and cwe_id.lower() != "null" else []
        
#         # Filter nulls
#         cve_id = [c for c in cve_id if c and c.lower() != "null"]
#         cwe_id = [c for c in cwe_id if c and c.lower() != "null"]
        
#         # Build evidence
#         evidence_parts = [
#             f"Template: {template_id}",
#             f"Matched At: {matched_at or host}"
#         ]
        
#         if match_type:
#             evidence_parts.append(f"Type: {match_type}")
        
#         if matcher_name:
#             evidence_parts.append(f"Matcher: {matcher_name}")
        
#         if extracted:
#             evidence_parts.append(f"Extracted: {', '.join(map(str, extracted[:5]))}")  # Limit to 5
        
#         if cve_id:
#             evidence_parts.append(f"CVE: {', '.join(cve_id)}")
        
#         if cwe_id:
#             evidence_parts.append(f"CWE: {', '.join(cwe_id)}")
        
#         evidence = "\n".join(evidence_parts)
        
#         # Enhanced description with references
#         full_description = description
#         if references:
#             full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])
        
#         return {
#             "title": template_name,
#             "description": full_description,
#             "severity": severity,
#             "evidence": evidence,
#             # Structured data for advanced reporting
#             "template_id": template_id,
#             "matched_at": matched_at or host,
#             "host": host,
#             "type": match_type,
#             "matcher_name": matcher_name,
#             "extracted_results": extracted,
#             "cve_id": cve_id,
#             "cwe_id": cwe_id,
#             "references": references,
#             "raw_json": json.dumps(data, indent=2)
#         }


"""
Nuclei vulnerability scanner module - FIXED VERSION.
Handles both JSON lines and empty output correctly.
"""

# import json
# from typing import List, Dict, Any
# from pentoolkit.modules.base import BinaryModule


# class NucleiModule(BinaryModule):
#     """
#     Nuclei vulnerability scanner with improved error handling.
    
#     FIXES:
#     - Handles empty output gracefully
#     - Better JSON parsing
#     - Improved severity mapping
#     - Template execution tracking
#     """
    
#     name = "nuclei"
#     description = "Template-based vulnerability scanner"
#     version = "1.3"
#     required_binary = "nuclei"

#     def run(self, target: str) -> str:
#         """
#         Execute nuclei on target with robust configuration.
#         """
#         # Ensure target has scheme
#         if not target.startswith(("http://", "https://")):
#             target = f"https://{target}"
        
#         # Build command with conservative settings
#         args = [
#             self.binary_path,
#             "-u", target,
#             "-silent",           # Suppress banner
#             "-nc",               # No color codes
#             "-json",             # JSON output
#             "-stats",            # Show statistics
#         ]
        
#         # Add templates root if configured
#         templates_root = self._get_config_value("templates_root")
#         if templates_root:
#             args.extend(["-t", templates_root])
#             self._log_info(f"Using templates from: {templates_root}")
#         else:
#             self._log_warning("No templates_root configured, using default templates")
        
#         # Add severity filter
#         severity = self._get_config_value("severity", "critical,high,medium,low,info")
#         args.extend(["-severity", severity])
        
#         # Rate limiting (prevent overwhelming target)
#         rate_limit = self._get_config_value("rate_limit", 150)
#         if rate_limit:
#             args.extend(["-rl", str(rate_limit)])
        
#         # Concurrency
#         concurrency = self._get_config_value("concurrency", 25)
#         if concurrency:
#             args.extend(["-c", str(concurrency)])
        
#         # Retries
#         args.extend(["-retries", "1"])
        
#         # Timeout per template
#         template_timeout = self._get_config_value("template_timeout", 10)
#         if template_timeout:
#             args.extend(["-timeout", str(template_timeout)])
        
#         # Disable interactsh (can cause hangs)
#         args.append("-ni")
        
#         # Disable update check
#         args.append("-duc")
        
#         self._log_info(f"Scanning: {target} with nuclei")
#         self._log_debug(f"Command: {' '.join(args)}")
        
#         # Execute with extended timeout
#         timeout = self._get_config_value("timeout", 600)  # 10 minutes default
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_warning(f"Nuclei timed out after {timeout}s (partial results may exist)")
        
#         if not result.success:
#             # Nuclei returns non-zero if templates have issues, but may still produce results
#             self._log_debug(f"Nuclei exit code {result.returncode}: {result.stderr[:200]}")
        
#         # Store both stdout and stderr (stats are in stderr)
#         self.raw_output = result.stdout
#         self._nuclei_stats = result.stderr  # Save stats separately
        
#         self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """
#         Parse nuclei JSON output with robust error handling.
#         """
#         findings = []
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             # Check if we have stats in stderr
#             stats = getattr(self, '_nuclei_stats', '')
            
#             # Parse stats to see if templates actually ran
#             if "templates loaded" in stats.lower():
#                 self._log_info("Nuclei scan completed with no vulnerabilities found")
#                 self._add_finding(
#                     title="No Vulnerabilities Detected",
#                     description="Nuclei scan completed successfully but found no matching templates",
#                     severity="info",
#                     evidence=f"Nuclei executed but returned no matches.\n\nStats:\n{stats[:500]}"
#                 )
#             else:
#                 self._log_warning("Nuclei produced no output (may have failed to load templates)")
#                 self._add_finding(
#                     title="Nuclei Scan Failed",
#                     description="Nuclei did not execute successfully (check template path and configuration)",
#                     severity="info",
#                     evidence=stats[:500] if stats else "No output or stats available"
#                 )
            
#             return self.findings
        
#         # Parse JSON lines (nuclei outputs one JSON per finding)
#         vuln_count = 0
#         parse_errors = 0
        
#         for line_num, line in enumerate(output.splitlines(), 1):
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 finding = self._parse_nuclei_finding(item)
#                 if finding:
#                     findings.append(finding)
#                     vuln_count += 1
            
#             except json.JSONDecodeError as e:
#                 parse_errors += 1
#                 if parse_errors <= 3:  # Only log first 3 errors
#                     self._log_warning(f"Failed to parse JSON line {line_num}: {e}")
#                     self._log_debug(f"Problematic line: {line[:100]}")
#                 continue
            
#             except Exception as e:
#                 self._log_error(f"Error parsing finding at line {line_num}: {e}", exc_info=True)
#                 continue
        
#         if parse_errors > 0:
#             self._log_warning(f"Total JSON parse errors: {parse_errors}")
        
#         if vuln_count > 0:
#             self._log_info(f"Found {vuln_count} potential vulnerabilities")
#         elif not findings:
#             # If we had output but no findings parsed, something went wrong
#             self._add_finding(
#                 title="Nuclei Output Parse Error",
#                 description=f"Nuclei produced output but no valid findings could be parsed ({parse_errors} parse errors)",
#                 severity="info",
#                 evidence=output[:1000]
#             )
        
#         self.findings = findings
#         return findings

#     def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Parse a single nuclei JSON finding with enhanced data extraction.
#         """
#         # Extract info section
#         info = data.get("info", {})
        
#         # Template details
#         template_id = data.get("template-id") or data.get("templateID") or "unknown"
#         template_name = info.get("name", template_id)
        
#         # Severity (normalize)
#         severity = info.get("severity", "info").lower()
#         if severity not in {"critical", "high", "medium", "low", "info"}:
#             severity = "info"
        
#         # Description
#         description = info.get("description", "")
#         if not description:
#             description = f"Nuclei template match: {template_name}"
        
#         # Matched URL
#         matched_at = data.get("matched-at") or data.get("matched") or data.get("host", "")
#         host = data.get("host", "")
        
#         # Type of match
#         match_type = data.get("type", "")
        
#         # Matcher name (what triggered the match)
#         matcher_name = data.get("matcher-name", "")
        
#         # Extracted results (if any)
#         extracted = data.get("extracted-results", [])
        
#         # References
#         references = info.get("reference", [])
#         if isinstance(references, str):
#             references = [references]
        
#         # Filter out null/empty references
#         references = [r for r in references if r and r.lower() != "null"]
        
#         # Classification (CVE, CWE, etc.)
#         classification = info.get("classification", {})
#         cve_id = classification.get("cve-id", [])
#         cwe_id = classification.get("cwe-id", [])
        
#         # Normalize CVE/CWE (can be string or list)
#         if isinstance(cve_id, str):
#             cve_id = [cve_id] if cve_id and cve_id.lower() != "null" else []
#         if isinstance(cwe_id, str):
#             cwe_id = [cwe_id] if cwe_id and cwe_id.lower() != "null" else []
        
#         # Filter nulls
#         cve_id = [c for c in cve_id if c and c.lower() != "null"]
#         cwe_id = [c for c in cwe_id if c and c.lower() != "null"]
        
#         # Build evidence
#         evidence_parts = [
#             f"Template: {template_id}",
#             f"Matched At: {matched_at or host}"
#         ]
        
#         if match_type:
#             evidence_parts.append(f"Type: {match_type}")
        
#         if matcher_name:
#             evidence_parts.append(f"Matcher: {matcher_name}")
        
#         if extracted:
#             evidence_parts.append(f"Extracted: {', '.join(map(str, extracted[:5]))}")  # Limit to 5
        
#         if cve_id:
#             evidence_parts.append(f"CVE: {', '.join(cve_id)}")
        
#         if cwe_id:
#             evidence_parts.append(f"CWE: {', '.join(cwe_id)}")
        
#         evidence = "\n".join(evidence_parts)
        
#         # Enhanced description with references
#         full_description = description
#         if references:
#             full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])
        
#         return {
#             "title": template_name,
#             "description": full_description,
#             "severity": severity,
#             "evidence": evidence,
#             # Structured data for advanced reporting
#             "template_id": template_id,
#             "matched_at": matched_at or host,
#             "host": host,
#             "type": match_type,
#             "matcher_name": matcher_name,
#             "extracted_results": extracted,
#             "cve_id": cve_id,
#             "cwe_id": cwe_id,
#             "references": references,
#             "raw_json": json.dumps(data, indent=2)
#         }







# """
# Nuclei vulnerability scanner - FIXED VERSION
# Handles None values in command args properly.
# """

# import json
# from typing import List, Dict, Any
# from pentoolkit.modules.base import BinaryModule


# class NucleiModule(BinaryModule):
#     """
#     Nuclei vulnerability scanner.
    
#     FIXES:
#     - ✅ Filters None values from command args
#     - ✅ Better error handling
#     - ✅ Proper stats tracking
#     """
    
#     name = "nuclei"
#     description = "Template-based vulnerability scanner"
#     version = "1.4"
#     required_binary = "nuclei"

#     def run(self, target: str) -> str:
#         """Execute nuclei on target."""
#         # Ensure target has scheme
#         if not target.startswith(("http://", "https://")):
#             target = f"https://{target}"
        
#         # Build command
#         args = [
#             self.binary_path,
#             "-u", target,
#             "-silent",
#             "-nc",
#             "-json",
#             "-stats",
#         ]
        
#         # Add templates root if configured
#         templates_root = self._get_config_value("templates_root")
#         if templates_root:
#             args.extend(["-t", templates_root])
#             self._log_info(f"Using templates: {templates_root}")
        
#         # Add severity filter
#         severity = self._get_config_value("severity", "critical,high,medium,low,info")
#         if severity:
#             args.extend(["-severity", severity])
        
#         # Rate limiting
#         rate_limit = self._get_config_value("rate_limit", 150)
#         if rate_limit:
#             args.extend(["-rl", str(rate_limit)])
        
#         # Concurrency
#         concurrency = self._get_config_value("concurrency", 25)
#         if concurrency:
#             args.extend(["-c", str(concurrency)])
        
#         # Retries
#         args.extend(["-retries", "1"])
        
#         # Timeout per template
#         template_timeout = self._get_config_value("template_timeout", 10)
#         if template_timeout:
#             args.extend(["-timeout", str(template_timeout)])
        
#         # Disable interactsh and update check
#         args.extend(["-ni", "-duc"])
        
#         # ✅ CRITICAL FIX: Filter None values from args
#         args = [str(arg) for arg in args if arg is not None]
        
#         self._log_info(f"Scanning: {target}")
#         self._log_debug(f"Command: {' '.join(args)}")
        
#         # Execute
#         timeout = self._get_config_value("timeout", 600)
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_warning(f"Nuclei timed out after {timeout}s")
        
#         # Store outputs
#         self.raw_output = result.stdout
#         self._nuclei_stats = result.stderr
        
#         self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """Parse nuclei JSON output."""
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             stats = getattr(self, '_nuclei_stats', '')
            
#             if "templates loaded" in stats.lower():
#                 self._log_info("Nuclei: No vulnerabilities found")
#                 self._add_finding(
#                     title="No Vulnerabilities Detected",
#                     description="Nuclei scan completed successfully",
#                     severity="info",
#                     evidence=f"No matches found.\n\nStats:\n{stats[:500]}"
#                 )
#             else:
#                 self._log_warning("Nuclei: No output")
#                 self._add_finding(
#                     title="Nuclei Scan Failed",
#                     description="Nuclei did not execute successfully",
#                     severity="info",
#                     evidence=stats[:500] if stats else "No output"
#                 )
            
#             return self.findings
        
#         # Parse JSON lines
#         vuln_count = 0
#         parse_errors = 0
        
#         for line_num, line in enumerate(output.splitlines(), 1):
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 finding = self._parse_nuclei_finding(item)
#                 if finding:
#                     self._add_finding(**finding)
#                     vuln_count += 1
            
#             except json.JSONDecodeError as e:
#                 parse_errors += 1
#                 if parse_errors <= 3:
#                     self._log_warning(f"JSON parse error line {line_num}: {e}")
#                 continue
            
#             except Exception as e:
#                 self._log_error(f"Error parsing line {line_num}: {e}")
#                 continue
        
#         if vuln_count > 0:
#             self._log_info(f"Found {vuln_count} vulnerabilities")
#         elif not self.findings:
#             self._add_finding(
#                 title="Nuclei Output Parse Error",
#                 description=f"No valid findings parsed ({parse_errors} errors)",
#                 severity="info",
#                 evidence=output[:1000]
#             )
        
#         return self.findings

#     def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """Parse single nuclei JSON finding."""
#         info = data.get("info", {})
        
#         template_id = data.get("template-id") or data.get("templateID") or "unknown"
#         template_name = info.get("name", template_id)
        
#         # Severity
#         severity = info.get("severity", "info").lower()
#         if severity not in {"critical", "high", "medium", "low", "info"}:
#             severity = "info"
        
#         # Description
#         description = info.get("description", f"Nuclei match: {template_name}")
        
#         # Matched URL
#         matched_at = data.get("matched-at") or data.get("matched") or data.get("host", "")
#         host = data.get("host", "")
        
#         # Type and matcher
#         match_type = data.get("type", "")
#         matcher_name = data.get("matcher-name", "")
        
#         # Extracted results
#         extracted = data.get("extracted-results", [])
        
#         # References
#         references = info.get("reference", [])
#         if isinstance(references, str):
#             references = [references]
#         references = [r for r in references if r and r.lower() != "null"]
        
#         # CVE/CWE
#         classification = info.get("classification", {})
#         cve_id = classification.get("cve-id", [])
#         cwe_id = classification.get("cwe-id", [])
        
#         if isinstance(cve_id, str):
#             cve_id = [cve_id] if cve_id and cve_id.lower() != "null" else []
#         if isinstance(cwe_id, str):
#             cwe_id = [cwe_id] if cwe_id and cwe_id.lower() != "null" else []
        
#         cve_id = [c for c in cve_id if c and c.lower() != "null"]
#         cwe_id = [c for c in cwe_id if c and c.lower() != "null"]
        
#         # Build evidence
#         evidence_parts = [
#             f"Template: {template_id}",
#             f"Matched At: {matched_at or host}"
#         ]
        
#         if match_type:
#             evidence_parts.append(f"Type: {match_type}")
#         if matcher_name:
#             evidence_parts.append(f"Matcher: {matcher_name}")
#         if extracted:
#             evidence_parts.append(f"Extracted: {', '.join(map(str, extracted[:5]))}")
#         if cve_id:
#             evidence_parts.append(f"CVE: {', '.join(cve_id)}")
#         if cwe_id:
#             evidence_parts.append(f"CWE: {', '.join(cwe_id)}")
        
#         evidence = "\n".join(evidence_parts)
        
#         # Enhanced description
#         full_description = description
#         if references:
#             full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])
        
#         return {
#             "title": template_name,
#             "description": full_description,
#             "severity": severity,
#             "evidence": evidence,
#             "template_id": template_id,
#             "matched_at": matched_at or host,
#             "cve_id": cve_id,
#             "cwe_id": cwe_id
#         }








# """
# Nuclei vulnerability scanner - FIXED VERSION
# Handles None values in command args properly.
# """

# import json
# from typing import List, Dict, Any
# from pentoolkit.modules.base import BinaryModule


# class NucleiModule(BinaryModule):
#     """
#     Nuclei vulnerability scanner.
    
#     FIXES:
#     - ✅ Filters None values from command args
#     - ✅ Better error handling
#     - ✅ Proper stats tracking
#     """
    
#     name = "nuclei"
#     description = "Template-based vulnerability scanner"
#     version = "1.4"
#     required_binary = "nuclei"

#     def run(self, target: str) -> str:
#         """Execute nuclei on target."""
#         # Ensure target has scheme
#         if not target.startswith(("http://", "https://")):
#             target = f"https://{target}"
        
#         # Build command
#         args = [
#             self.binary_path,
#             "-u", target,
#             "-silent",
#             "-nc",
#             "-jsonl",  # ✅ FIXED: Use -jsonl instead of -json (newer nuclei versions)
#             "-stats",
#         ]
        
#         # Add templates root if configured
#         templates_root = self._get_config_value("templates_root")
#         if templates_root:
#             args.extend(["-t", templates_root])
#             self._log_info(f"Using templates: {templates_root}")
        
#         # Add severity filter
#         severity = self._get_config_value("severity", "critical,high,medium,low,info")
#         if severity:
#             args.extend(["-severity", severity])
        
#         # Rate limiting
#         rate_limit = self._get_config_value("rate_limit", 150)
#         if rate_limit:
#             args.extend(["-rl", str(rate_limit)])
        
#         # Concurrency
#         concurrency = self._get_config_value("concurrency", 25)
#         if concurrency:
#             args.extend(["-c", str(concurrency)])
        
#         # Retries
#         args.extend(["-retries", "1"])
        
#         # Timeout per template
#         template_timeout = self._get_config_value("template_timeout", 10)
#         if template_timeout:
#             args.extend(["-timeout", str(template_timeout)])
        
#         # Disable interactsh and update check
#         args.extend(["-ni", "-duc"])
        
#         # ✅ CRITICAL FIX: Filter None values from args
#         args = [str(arg) for arg in args if arg is not None]
        
#         self._log_info(f"Scanning: {target}")
#         self._log_debug(f"Command: {' '.join(args)}")
        
#         # Execute
#         timeout = self._get_config_value("timeout", 600)
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_warning(f"Nuclei timed out after {timeout}s")
        
#         # Store outputs
#         self.raw_output = result.stdout
#         self._nuclei_stats = result.stderr
        
#         self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """Parse nuclei JSON output."""
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             stats = getattr(self, '_nuclei_stats', '')
            
#             if "templates loaded" in stats.lower():
#                 self._log_info("Nuclei: No vulnerabilities found")
#                 self._add_finding(
#                     title="No Vulnerabilities Detected",
#                     description="Nuclei scan completed successfully",
#                     severity="info",
#                     evidence=f"No matches found.\n\nStats:\n{stats[:500]}"
#                 )
#             else:
#                 self._log_warning("Nuclei: No output")
#                 self._add_finding(
#                     title="Nuclei Scan Failed",
#                     description="Nuclei did not execute successfully",
#                     severity="info",
#                     evidence=stats[:500] if stats else "No output"
#                 )
            
#             return self.findings
        
#         # Parse JSON lines
#         vuln_count = 0
#         parse_errors = 0
        
#         for line_num, line in enumerate(output.splitlines(), 1):
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 finding = self._parse_nuclei_finding(item)
#                 if finding:
#                     self._add_finding(**finding)
#                     vuln_count += 1
            
#             except json.JSONDecodeError as e:
#                 parse_errors += 1
#                 if parse_errors <= 3:
#                     self._log_warning(f"JSON parse error line {line_num}: {e}")
#                 continue
            
#             except Exception as e:
#                 self._log_error(f"Error parsing line {line_num}: {e}")
#                 continue
        
#         if vuln_count > 0:
#             self._log_info(f"Found {vuln_count} vulnerabilities")
#         elif not self.findings:
#             self._add_finding(
#                 title="Nuclei Output Parse Error",
#                 description=f"No valid findings parsed ({parse_errors} errors)",
#                 severity="info",
#                 evidence=output[:1000]
#             )
        
#         return self.findings

#     def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """Parse single nuclei JSON finding."""
#         info = data.get("info", {})
        
#         template_id = data.get("template-id") or data.get("templateID") or "unknown"
#         template_name = info.get("name", template_id)
        
#         # Severity
#         severity = info.get("severity", "info").lower()
#         if severity not in {"critical", "high", "medium", "low", "info"}:
#             severity = "info"
        
#         # Description
#         description = info.get("description", f"Nuclei match: {template_name}")
        
#         # Matched URL
#         matched_at = data.get("matched-at") or data.get("matched") or data.get("host", "")
#         host = data.get("host", "")
        
#         # Type and matcher
#         match_type = data.get("type", "")
#         matcher_name = data.get("matcher-name", "")
        
#         # Extracted results
#         extracted = data.get("extracted-results", [])
        
#         # References
#         references = info.get("reference", [])
#         if isinstance(references, str):
#             references = [references]
#         references = [r for r in references if r and r.lower() != "null"]
        
#         # CVE/CWE
#         classification = info.get("classification", {})
#         cve_id = classification.get("cve-id", [])
#         cwe_id = classification.get("cwe-id", [])
        
#         if isinstance(cve_id, str):
#             cve_id = [cve_id] if cve_id and cve_id.lower() != "null" else []
#         if isinstance(cwe_id, str):
#             cwe_id = [cwe_id] if cwe_id and cwe_id.lower() != "null" else []
        
#         cve_id = [c for c in cve_id if c and c.lower() != "null"]
#         cwe_id = [c for c in cwe_id if c and c.lower() != "null"]
        
#         # Build evidence
#         evidence_parts = [
#             f"Template: {template_id}",
#             f"Matched At: {matched_at or host}"
#         ]
        
#         if match_type:
#             evidence_parts.append(f"Type: {match_type}")
#         if matcher_name:
#             evidence_parts.append(f"Matcher: {matcher_name}")
#         if extracted:
#             evidence_parts.append(f"Extracted: {', '.join(map(str, extracted[:5]))}")
#         if cve_id:
#             evidence_parts.append(f"CVE: {', '.join(cve_id)}")
#         if cwe_id:
#             evidence_parts.append(f"CWE: {', '.join(cwe_id)}")
        
#         evidence = "\n".join(evidence_parts)
        
#         # Enhanced description
#         full_description = description
#         if references:
#             full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])
        
#         return {
#             "title": template_name,
#             "description": full_description,
#             "severity": severity,
#             "evidence": evidence,
#             "template_id": template_id,
#             "matched_at": matched_at or host,
#             "cve_id": cve_id,
#             "cwe_id": cwe_id
#         }











# """
# Nuclei vulnerability scanner module - FIXED VERSION.
# Handles both JSON lines and empty output correctly.
# """

# import json
# from typing import List, Dict, Any
# from pentoolkit.modules.base import BinaryModule


# class NucleiModule(BinaryModule):
#     """
#     Nuclei vulnerability scanner with improved error handling.
    
#     FIXES:
#     - Handles empty output gracefully
#     - Better JSON parsing
#     - Improved severity mapping
#     - Template execution tracking
#     """
    
#     name = "nuclei"
#     description = "Template-based vulnerability scanner"
#     version = "1.3"
#     required_binary = "nuclei"

#     def run(self, target: str) -> str:
#         """
#         Execute nuclei on target with robust configuration.
#         """
#         # Ensure target has scheme
#         if not target.startswith(("http://", "https://")):
#             target = f"https://{target}"
        
#         # Build command with conservative settings
#         args = [
#             self.binary_path,
#             "-u", target,
#             "-silent",           # Suppress banner
#             "-nc",               # No color codes
#             "-json",             # JSON output
#             "-stats",            # Show statistics
#         ]
        
#         # Add templates root if configured
#         templates_root = self._get_config_value("templates_root")
#         if templates_root:
#             args.extend(["-t", templates_root])
#             self._log_info(f"Using templates from: {templates_root}")
#         else:
#             self._log_warning("No templates_root configured, using default templates")
        
#         # Add severity filter
#         severity = self._get_config_value("severity", "critical,high,medium,low,info")
#         args.extend(["-severity", severity])
        
#         # Rate limiting (prevent overwhelming target)
#         rate_limit = self._get_config_value("rate_limit", 150)
#         if rate_limit:
#             args.extend(["-rl", str(rate_limit)])
        
#         # Concurrency
#         concurrency = self._get_config_value("concurrency", 25)
#         if concurrency:
#             args.extend(["-c", str(concurrency)])
        
#         # Retries
#         args.extend(["-retries", "1"])
        
#         # Timeout per template
#         template_timeout = self._get_config_value("template_timeout", 10)
#         if template_timeout:
#             args.extend(["-timeout", str(template_timeout)])
        
#         # Disable interactsh (can cause hangs)
#         args.append("-ni")
        
#         # Disable update check
#         args.append("-duc")
        
#         self._log_info(f"Scanning: {target} with nuclei")
#         self._log_debug(f"Command: {' '.join(args)}")
        
#         # Execute with extended timeout
#         timeout = self._get_config_value("timeout", 600)  # 10 minutes default
#         result = self._run_command(args, timeout=timeout)
        
#         if result.timed_out:
#             self._log_warning(f"Nuclei timed out after {timeout}s (partial results may exist)")
        
#         if not result.success:
#             # Nuclei returns non-zero if templates have issues, but may still produce results
#             self._log_debug(f"Nuclei exit code {result.returncode}: {result.stderr[:200]}")
        
#         # Store both stdout and stderr (stats are in stderr)
#         self.raw_output = result.stdout
#         self._nuclei_stats = result.stderr  # Save stats separately
        
#         self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         """
#         Parse nuclei JSON output with robust error handling.
#         """
#         findings = []
#         output = (self.raw_output or "").strip()
        
#         if not output:
#             # Check if we have stats in stderr
#             stats = getattr(self, '_nuclei_stats', '')
            
#             # Parse stats to see if templates actually ran
#             if "templates loaded" in stats.lower():
#                 self._log_info("Nuclei scan completed with no vulnerabilities found")
#                 self._add_finding(
#                     title="No Vulnerabilities Detected",
#                     description="Nuclei scan completed successfully but found no matching templates",
#                     severity="info",
#                     evidence=f"Nuclei executed but returned no matches.\n\nStats:\n{stats[:500]}"
#                 )
#             else:
#                 self._log_warning("Nuclei produced no output (may have failed to load templates)")
#                 self._add_finding(
#                     title="Nuclei Scan Failed",
#                     description="Nuclei did not execute successfully (check template path and configuration)",
#                     severity="info",
#                     evidence=stats[:500] if stats else "No output or stats available"
#                 )
            
#             return self.findings
        
#         # Parse JSON lines (nuclei outputs one JSON per finding)
#         vuln_count = 0
#         parse_errors = 0
        
#         for line_num, line in enumerate(output.splitlines(), 1):
#             line = line.strip()
#             if not line:
#                 continue
            
#             try:
#                 item = json.loads(line)
#                 finding = self._parse_nuclei_finding(item)
#                 if finding:
#                     findings.append(finding)
#                     vuln_count += 1
            
#             except json.JSONDecodeError as e:
#                 parse_errors += 1
#                 if parse_errors <= 3:  # Only log first 3 errors
#                     self._log_warning(f"Failed to parse JSON line {line_num}: {e}")
#                     self._log_debug(f"Problematic line: {line[:100]}")
#                 continue
            
#             except Exception as e:
#                 self._log_error(f"Error parsing finding at line {line_num}: {e}", exc_info=True)
#                 continue
        
#         if parse_errors > 0:
#             self._log_warning(f"Total JSON parse errors: {parse_errors}")
        
#         if vuln_count > 0:
#             self._log_info(f"Found {vuln_count} potential vulnerabilities")
#         elif not findings:
#             # If we had output but no findings parsed, something went wrong
#             self._add_finding(
#                 title="Nuclei Output Parse Error",
#                 description=f"Nuclei produced output but no valid findings could be parsed ({parse_errors} parse errors)",
#                 severity="info",
#                 evidence=output[:1000]
#             )
        
#         self.findings = findings
#         return findings

#     def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Parse a single nuclei JSON finding with enhanced data extraction.
#         """
#         # Extract info section
#         info = data.get("info", {})
        
#         # Template details
#         template_id = data.get("template-id") or data.get("templateID") or "unknown"
#         template_name = info.get("name", template_id)
        
#         # Severity (normalize)
#         severity = info.get("severity", "info").lower()
#         if severity not in {"critical", "high", "medium", "low", "info"}:
#             severity = "info"
        
#         # Description
#         description = info.get("description", "")
#         if not description:
#             description = f"Nuclei template match: {template_name}"
        
#         # Matched URL
#         matched_at = data.get("matched-at") or data.get("matched") or data.get("host", "")
#         host = data.get("host", "")
        
#         # Type of match
#         match_type = data.get("type", "")
        
#         # Matcher name (what triggered the match)
#         matcher_name = data.get("matcher-name", "")
        
#         # Extracted results (if any)
#         extracted = data.get("extracted-results", [])
        
#         # References
#         references = info.get("reference", [])
#         if isinstance(references, str):
#             references = [references]
        
#         # Filter out null/empty references
#         references = [r for r in references if r and r.lower() != "null"]
        
#         # Classification (CVE, CWE, etc.)
#         classification = info.get("classification", {})
#         cve_id = classification.get("cve-id", [])
#         cwe_id = classification.get("cwe-id", [])
        
#         # Normalize CVE/CWE (can be string or list)
#         if isinstance(cve_id, str):
#             cve_id = [cve_id] if cve_id and cve_id.lower() != "null" else []
#         if isinstance(cwe_id, str):
#             cwe_id = [cwe_id] if cwe_id and cwe_id.lower() != "null" else []
        
#         # Filter nulls
#         cve_id = [c for c in cve_id if c and c.lower() != "null"]
#         cwe_id = [c for c in cwe_id if c and c.lower() != "null"]
        
#         # Build evidence
#         evidence_parts = [
#             f"Template: {template_id}",
#             f"Matched At: {matched_at or host}"
#         ]
        
#         if match_type:
#             evidence_parts.append(f"Type: {match_type}")
        
#         if matcher_name:
#             evidence_parts.append(f"Matcher: {matcher_name}")
        
#         if extracted:
#             evidence_parts.append(f"Extracted: {', '.join(map(str, extracted[:5]))}")  # Limit to 5
        
#         if cve_id:
#             evidence_parts.append(f"CVE: {', '.join(cve_id)}")
        
#         if cwe_id:
#             evidence_parts.append(f"CWE: {', '.join(cwe_id)}")
        
#         evidence = "\n".join(evidence_parts)
        
#         # Enhanced description with references
#         full_description = description
#         if references:
#             full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])
        
#         return {
#             "title": template_name,
#             "description": full_description,
#             "severity": severity,
#             "evidence": evidence,
#             # Structured data for advanced reporting
#             "template_id": template_id,
#             "matched_at": matched_at or host,
#             "host": host,
#             "type": match_type,
#             "matcher_name": matcher_name,
#             "extracted_results": extracted,
#             "cve_id": cve_id,
#             "cwe_id": cwe_id,
#             "references": references,
#             "raw_json": json.dumps(data, indent=2)
#         }









"""
Nuclei vulnerability scanner - FIXED VERSION
Handles None values in command args properly.
"""

import json
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class NucleiModule(BinaryModule):
    """
    Nuclei vulnerability scanner.
    
    FIXES:
    - ✅ Filters None values from command args
    - ✅ Better error handling
    - ✅ Proper stats tracking
    """
    
    name = "nuclei"
    description = "Template-based vulnerability scanner"
    version = "1.4"
    required_binary = "nuclei"

    def run(self, target: str) -> str:
        """Execute nuclei on target."""
        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        # Build command
        args = [
            self.binary_path,
            "-u", target,
            "-silent",
            "-nc",
            "-json",
            "-stats",
        ]
        
        # Add templates root if configured
        templates_root = self._get_config_value("templates_root")
        if templates_root:
            args.extend(["-t", templates_root])
            self._log_info(f"Using templates: {templates_root}")
        
        # Add severity filter
        severity = self._get_config_value("severity", "critical,high,medium,low,info")
        if severity:
            args.extend(["-severity", severity])
        
        # Rate limiting
        rate_limit = self._get_config_value("rate_limit", 150)
        if rate_limit:
            args.extend(["-rl", str(rate_limit)])
        
        # Concurrency
        concurrency = self._get_config_value("concurrency", 25)
        if concurrency:
            args.extend(["-c", str(concurrency)])
        
        # Retries
        args.extend(["-retries", "1"])
        
        # Timeout per template
        template_timeout = self._get_config_value("template_timeout", 10)
        if template_timeout:
            args.extend(["-timeout", str(template_timeout)])
        
        # Disable interactsh and update check
        args.extend(["-ni", "-duc"])
        
        # ✅ CRITICAL FIX: Filter None values from args
        args = [str(arg) for arg in args if arg is not None]
        
        self._log_info(f"Scanning: {target}")
        self._log_debug(f"Command: {' '.join(args)}")
        
        # Execute
        timeout = self._get_config_value("timeout", 600)
        result = self._run_command(args, timeout=timeout)
        
        if result.timed_out:
            self._log_warning(f"Nuclei timed out after {timeout}s")
        
        # Store outputs
        self.raw_output = result.stdout
        self._nuclei_stats = result.stderr
        
        self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """Parse nuclei JSON output."""
        output = (self.raw_output or "").strip()
        
        if not output:
            stats = getattr(self, '_nuclei_stats', '')
            
            if "templates loaded" in stats.lower():
                self._log_info("Nuclei: No vulnerabilities found")
                self._add_finding(
                    title="No Vulnerabilities Detected",
                    description="Nuclei scan completed successfully",
                    severity="info",
                    evidence=f"No matches found.\n\nStats:\n{stats[:500]}"
                )
            else:
                self._log_warning("Nuclei: No output")
                self._add_finding(
                    title="Nuclei Scan Failed",
                    description="Nuclei did not execute successfully",
                    severity="info",
                    evidence=stats[:500] if stats else "No output"
                )
            
            return self.findings
        
        # Parse JSON lines
        vuln_count = 0
        parse_errors = 0
        
        for line_num, line in enumerate(output.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
                finding = self._parse_nuclei_finding(item)
                if finding:
                    self._add_finding(**finding)
                    vuln_count += 1
            
            except json.JSONDecodeError as e:
                parse_errors += 1
                if parse_errors <= 3:
                    self._log_warning(f"JSON parse error line {line_num}: {e}")
                continue
            
            except Exception as e:
                self._log_error(f"Error parsing line {line_num}: {e}")
                continue
        
        if vuln_count > 0:
            self._log_info(f"Found {vuln_count} vulnerabilities")
        elif not self.findings:
            self._add_finding(
                title="Nuclei Output Parse Error",
                description=f"No valid findings parsed ({parse_errors} errors)",
                severity="info",
                evidence=output[:1000]
            )
        
        return self.findings

    def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse single nuclei JSON finding."""
        info = data.get("info", {})
        
        template_id = data.get("template-id") or data.get("templateID") or "unknown"
        template_name = info.get("name", template_id)
        
        # Severity
        severity = info.get("severity", "info").lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "info"
        
        # Description
        description = info.get("description", f"Nuclei match: {template_name}")
        
        # Matched URL
        matched_at = data.get("matched-at") or data.get("matched") or data.get("host", "")
        host = data.get("host", "")
        
        # Type and matcher
        match_type = data.get("type", "")
        matcher_name = data.get("matcher-name", "")
        
        # Extracted results
        extracted = data.get("extracted-results", [])
        
        # References
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        references = [r for r in references if r and r.lower() != "null"]
        
        # CVE/CWE
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id", [])
        cwe_id = classification.get("cwe-id", [])
        
        if isinstance(cve_id, str):
            cve_id = [cve_id] if cve_id and cve_id.lower() != "null" else []
        if isinstance(cwe_id, str):
            cwe_id = [cwe_id] if cwe_id and cwe_id.lower() != "null" else []
        
        cve_id = [c for c in cve_id if c and c.lower() != "null"]
        cwe_id = [c for c in cwe_id if c and c.lower() != "null"]
        
        # Build evidence
        evidence_parts = [
            f"Template: {template_id}",
            f"Matched At: {matched_at or host}"
        ]
        
        if match_type:
            evidence_parts.append(f"Type: {match_type}")
        if matcher_name:
            evidence_parts.append(f"Matcher: {matcher_name}")
        if extracted:
            evidence_parts.append(f"Extracted: {', '.join(map(str, extracted[:5]))}")
        if cve_id:
            evidence_parts.append(f"CVE: {', '.join(cve_id)}")
        if cwe_id:
            evidence_parts.append(f"CWE: {', '.join(cwe_id)}")
        
        evidence = "\n".join(evidence_parts)
        
        # Enhanced description
        full_description = description
        if references:
            full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])
        
        return {
            "title": template_name,
            "description": full_description,
            "severity": severity,
            "evidence": evidence,
            "template_id": template_id,
            "matched_at": matched_at or host,
            "cve_id": cve_id,
            "cwe_id": cwe_id
        }
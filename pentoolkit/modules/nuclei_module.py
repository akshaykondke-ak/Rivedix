"""
Nuclei vulnerability scanner module with template-based detection.
"""

import json
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class NucleiModule(BinaryModule):
    """
    Nuclei vulnerability scanner.
    
    Features:
        - Template-based vulnerability detection
        - Severity filtering
        - Rate limiting
        - Concurrent template execution
    """
    
    name = "nuclei"
    description = "Template-based vulnerability scanner"
    version = "1.2"
    required_binary = "nuclei"

    def run(self, target: str) -> str:
        """
        Execute nuclei on target.
        
        Args:
            target: Target URL or hostname
            
        Returns:
            JSON output from nuclei
        """
        # Ensure target has scheme for nuclei
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        # Build command
        args = [
            self.binary_path,
            "-u", target,
            "-silent",
            "-json"
        ]
        
        # Add templates root if configured
        templates_root = self._get_config_value("templates_root")
        if templates_root:
            args.extend(["-t", templates_root])
            self._log_info(f"Using templates from: {templates_root}")
        
        # Add severity filter
        severity = self._get_config_value("severity", "critical,high,medium,low,info")
        args.extend(["-severity", severity])
        
        # Add rate limiting
        rate_limit = self._get_config_value("rate_limit", 50)
        args.extend(["-rl", str(rate_limit)])
        
        # Add concurrency
        concurrency = self._get_config_value("concurrency", 25)
        args.extend(["-c", str(concurrency)])
        
        # Add retries
        args.extend(["-retries", "1"])
        
        # Add timeout
        template_timeout = self._get_config_value("template_timeout", 10)
        args.extend(["-timeout", str(template_timeout)])
        
        # No metadata for cleaner output
        if self._get_config_value("no_meta", True):
            args.append("-no-meta")
        
        self._log_info(f"Scanning: {target} with nuclei")
        
        # Execute with extended timeout (nuclei can take a while)
        timeout = self._get_timeout()
        result = self._run_command(args, timeout=timeout)
        
        if result.timed_out:
            self._log_warning(f"Nuclei timed out after {timeout}s")
            # Don't fail completely - partial results may exist
        
        if not result.success and not result.has_output():
            self._log_warning(f"Nuclei failed: {result.stderr}")
        
        # Store output
        self.raw_output = result.stdout
        
        self._log_debug(f"Nuclei produced {len(self.raw_output)} bytes")
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """
        Parse nuclei JSON output.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        output = (self.raw_output or "").strip()
        
        if not output:
            self._log_info("Nuclei returned no findings (target may be secure)")
            self._add_finding(
                title="No Vulnerabilities Detected",
                description="Nuclei scan completed with no matches",
                severity="info",
                evidence="Clean scan result"
            )
            return self.findings
        
        # Parse JSON lines (nuclei outputs one JSON per line)
        vuln_count = 0
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
                finding = self._parse_nuclei_finding(item)
                if finding:
                    findings.append(finding)
                    vuln_count += 1
            
            except json.JSONDecodeError as e:
                self._log_warning(f"Failed to parse JSON line: {e}")
                continue
            
            except Exception as e:
                self._log_error(f"Error parsing finding: {e}", exc_info=True)
                continue
        
        if vuln_count > 0:
            self._log_info(f"Found {vuln_count} potential vulnerabilities")
        
        self.findings = findings
        return findings

    def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single nuclei JSON finding.
        
        Args:
            data: Parsed JSON object from nuclei
            
        Returns:
            Finding dictionary
        """
        # Extract info section
        info = data.get("info", {})
        
        # Template details
        template_id = data.get("template-id") or data.get("templateID") or "unknown"
        template_name = info.get("name", template_id)
        
        # Severity
        severity = info.get("severity", "info").lower()
        
        # Description
        description = info.get("description", "No description available")
        
        # Matched URL
        matched_at = data.get("matched-at") or data.get("matched") or "unknown"
        host = data.get("host", "")
        
        # Matcher name (what triggered the match)
        matcher_name = data.get("matcher-name", "")
        
        # Extracted results (if any)
        extracted = data.get("extracted-results", [])
        
        # References
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        
        # Classification (CVE, CWE, etc.)
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id", [])
        cwe_id = classification.get("cwe-id", [])
        
        # Build evidence
        evidence_parts = [
            f"Template: {template_id}",
            f"Matched: {matched_at}"
        ]
        
        if matcher_name:
            evidence_parts.append(f"Matcher: {matcher_name}")
        
        if extracted:
            evidence_parts.append(f"Extracted: {', '.join(map(str, extracted))}")
        
        if cve_id and cve_id != ["null"]:
            cve_list = ", ".join(cve_id) if isinstance(cve_id, list) else cve_id
            evidence_parts.append(f"CVE: {cve_list}")
        
        if cwe_id and cwe_id != ["null"]:
            cwe_list = ", ".join(cwe_id) if isinstance(cwe_id, list) else cwe_id
            evidence_parts.append(f"CWE: {cwe_list}")
        
        evidence = "\n".join(evidence_parts)
        
        # Add references to description
        full_description = description
        if references and references != ["null"]:
            ref_list = [r for r in references if r and r != "null"]
            if ref_list:
                full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in ref_list)
        
        return {
            "title": template_name,
            "description": full_description,
            "severity": severity,
            "evidence": evidence,
            # Structured data
            "template_id": template_id,
            "matched_at": matched_at,
            "host": host,
            "matcher_name": matcher_name,
            "extracted_results": extracted,
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "references": references,
            "raw_json": json.dumps(data, indent=2)
        }


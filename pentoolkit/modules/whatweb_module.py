
# ============================================================================
# pentoolkit/modules/whatweb_module.py
# ============================================================================

import json
import shutil
from typing import List, Dict, Any
from pentoolkit.modules.base import PentoolkitModule


class WhatWebModule(PentoolkitModule):
    """
    Web technology fingerprinting.
    
    Features:
        - Prefers wappalyzer (more accurate)
        - Falls back to whatweb
        - Detects CMS, frameworks, servers
    """
    
    name = "whatweb"
    description = "Web technology fingerprinting tool"
    version = "1.2"

    def prepare(self) -> None:
        """Prepare by detecting available tool."""
        # Try wappalyzer first
        self.wappalyzer_path = shutil.which("wappalyzer")
        self.whatweb_path = shutil.which("whatweb")
        
        if not (self.wappalyzer_path or self.whatweb_path):
            raise RuntimeError("Neither 'wappalyzer' nor 'whatweb' found in PATH")
        
        if self.wappalyzer_path:
            self._log_info("Using wappalyzer for fingerprinting")
            self.binary_path = self.wappalyzer_path
            self.use_wappalyzer = True
        else:
            self._log_info("Using whatweb for fingerprinting")
            self.binary_path = self.whatweb_path
            self.use_wappalyzer = False

    def run(self, target: str) -> str:
        """Execute fingerprinting on target."""
        # Ensure URL format
        if not target.startswith("http"):
            target = f"https://{target}"
        
        self._log_info(f"Fingerprinting: {target}")
        
        if self.use_wappalyzer:
            args = [self.binary_path, target, "--quiet", "--json"]
        else:
            args = [
                self.binary_path,
                "--aggression=3",
                "--user-agent=Mozilla/5.0",
                "--color=never",
                target
            ]
        
        timeout = self._get_timeout()
        result = self._run_command(args, timeout=timeout, check_returncode=False)
        
        self.raw_output = result.get_combined_output()
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """Parse fingerprinting output."""
        output = (self.raw_output or "").strip()
        
        if not output:
            self._add_finding(
                title="No Fingerprint Data",
                description="Tool did not return any data",
                severity="info",
                evidence="Empty output"
            )
            return self.findings
        
        if self.use_wappalyzer:
            self._parse_wappalyzer(output)
        else:
            self._parse_whatweb(output)
        
        return self.findings

    def _parse_wappalyzer(self, output: str):
        """Parse wappalyzer JSON output."""
        try:
            data = json.loads(output)
            technologies = data.get("technologies", [])
            
            if technologies:
                tech_names = [t.get("name") for t in technologies if isinstance(t, dict)]
                
                self._add_finding(
                    title="Web Technologies Detected",
                    description=", ".join(tech_names),
                    severity="info",
                    evidence=json.dumps(technologies, indent=2)
                )
            else:
                self._add_finding(
                    title="No Technologies Detected",
                    description="Wappalyzer did not detect any technologies",
                    severity="info",
                    evidence=output[:500]
                )
        
        except json.JSONDecodeError:
            self._log_error("Failed to parse wappalyzer JSON")
            self._add_finding(
                title="Fingerprint Parse Error",
                description="Could not parse wappalyzer output",
                severity="info",
                evidence=output[:500]
            )

    def _parse_whatweb(self, output: str):
        """Parse whatweb text output."""
        import re
        
        # Extract title
        title_match = re.search(r"Title\[([^\]]+)\]", output)
        
        # Extract server
        server_match = re.search(r"HTTPServer\[([^\]]+)\]", output)
        
        desc_parts = []
        if title_match:
            desc_parts.append(f"Title: {title_match.group(1)}")
        if server_match:
            desc_parts.append(f"Server: {server_match.group(1)}")
        
        description = "; ".join(desc_parts) if desc_parts else "Basic fingerprint data"
        
        self._add_finding(
            title="Web Server Fingerprint",
            description=description,
            severity="info",
            evidence=output[:1000]
        )


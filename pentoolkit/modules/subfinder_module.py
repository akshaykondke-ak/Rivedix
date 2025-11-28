
# ============================================================================
# pentoolkit/modules/subfinder_module.py
# ============================================================================

import json
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class SubfinderModule(BinaryModule):
    """
    Subdomain enumeration using Subfinder.
    
    Features:
        - Passive subdomain discovery
        - Multiple data sources
        - JSON output
    """
    
    name = "subfinder"
    description = "Passive subdomain enumeration tool"
    version = "1.1"
    required_binary = "subfinder"

    def run(self, target: str) -> str:
        """
        Execute subfinder on domain.
        
        Args:
            target: Target domain
            
        Returns:
            JSON output from subfinder
        """
        # Extract domain from URL if needed
        from pentoolkit.utils.helpers import extract_domain_from_url
        
        if target.startswith("http"):
            domain = extract_domain_from_url(target)
        else:
            domain = target.split("/")[0]
        
        self._log_info(f"Enumerating subdomains for: {domain}")
        
        # Build command
        args = [
            self.binary_path,
            "-d", domain,
            "-silent",
            "-json"
        ]
        
        # Execute
        timeout = self._get_timeout()
        result = self._run_command(args, timeout=timeout)
        
        if result.timed_out:
            self._log_warning(f"Subfinder timed out after {timeout}s")
        
        self.raw_output = result.stdout
        
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        """Parse subfinder JSON output."""
        findings = []
        output = (self.raw_output or "").strip()
        
        if not output:
            self._log_info("No subdomains found")
            self._add_finding(
                title="No Subdomains Discovered",
                description="Subfinder did not find any subdomains",
                severity="info",
                evidence="Empty result"
            )
            return self.findings
        
        # Parse JSON lines
        subdomains = []
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
                subdomain = item.get("host") or item.get("domain") or str(item)
                subdomains.append(subdomain)
            
            except json.JSONDecodeError:
                # Might be plain text
                if line:
                    subdomains.append(line)
        
        # Create findings
        if subdomains:
            # Summary finding
            self._add_finding(
                title=f"Discovered {len(subdomains)} Subdomain(s)",
                description=f"Found {len(subdomains)} subdomains via passive enumeration",
                severity="info",
                evidence="\n".join(subdomains[:50])  # Limit evidence
            )
            
            # Individual findings for each subdomain
            for subdomain in subdomains[:20]:  # Limit to 20 detailed findings
                self._add_finding(
                    title=f"Subdomain: {subdomain}",
                    description="Discovered subdomain",
                    severity="info",
                    evidence=subdomain
                )
        
        self.findings = findings
        return findings


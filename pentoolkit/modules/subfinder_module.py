
"""
Subfinder module - FIXED VERSION
Properly returns findings and counts subdomains.
"""

import json
from typing import List, Dict, Any
from pentoolkit.modules.base import BinaryModule


class SubfinderModule(BinaryModule):
    """
    Subdomain enumeration using Subfinder.
    
    FIXES:
    - ✅ Always returns self.findings
    - ✅ Proper subdomain counting
    - ✅ Handles both JSON and plain text
    """
    
    name = "subfinder"
    description = "Passive subdomain enumeration tool"
    version = "1.2"
    required_binary = "subfinder"

    def run(self, target: str) -> str:
        """Execute subfinder on domain."""
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
        """
        Parse subfinder JSON output.
        
        ✅ FIXED: Now properly returns self.findings!
        """
        output = (self.raw_output or "").strip()
        
        if not output:
            self._log_info("No subdomains found")
            self._add_finding(
                title="No Subdomains Discovered",
                description="Subfinder did not find any subdomains",
                severity="info",
                evidence="Empty result"
            )
            return self.findings  # ✅ CRITICAL FIX
        
        # Parse JSON lines
        subdomains = []
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            try:
                item = json.loads(line)
                subdomain = item.get("host") or item.get("domain") or str(item)
                if subdomain and subdomain not in subdomains:
                    subdomains.append(subdomain)
            
            except json.JSONDecodeError:
                # Might be plain text
                if line and line not in subdomains:
                    subdomains.append(line)
        
        # Create findings
        if subdomains:
            # Summary finding with count
            self._add_finding(
                title=f"Discovered {len(subdomains)} Subdomain(s)",
                description=f"Found {len(subdomains)} subdomains via passive enumeration",
                severity="info",
                evidence="\n".join(subdomains[:100]),  # Limit to 100
                subdomain_count=len(subdomains),  # ✅ Add count for report
                subdomains=subdomains  # ✅ Add full list for report
            )
            
            self._log_info(f"Found {len(subdomains)} subdomains")
        
        return self.findings  # ✅ CRITICAL FIX: Always return findings!
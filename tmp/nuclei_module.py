# pentoolkit/modules/nuclei_module.py
"""
Professional Nuclei integration (HYBRID mode, v3.x compatible).
Uses absolute template paths, JSON export, optimized flags.
"""

import subprocess
import shlex
import json
import tempfile
import os
import time
from typing import Dict, Any, List

from tmp.template_module import PentoolkitModule


class NucleiModule(PentoolkitModule):
    name = "nuclei"
    description = "Run Nuclei vulnerability scanner (hybrid mode)"
    version = "3.hybrid"

    # -------------------------------------------------------
    # Helpers
    # -------------------------------------------------------

    def _normalize_target(self, target: str) -> str:
        t = target.strip()
        if t.startswith("http://") or t.startswith("https://"):
            return t
        return f"https://{t}"

    def _choose_templates(self, mode: str, root: str) -> List[str]:
        """Return ABSOLUTE template directories for nuclei."""
        return {
            "fast": [
                f"{root}/cves/",
                f"{root}/exposures/",
                f"{root}/misconfiguration/",
                f"{root}/technologies/",
            ],
            "hybrid": [
                f"{root}/cves/",
                f"{root}/exposures/",
                f"{root}/misconfiguration/",
                f"{root}/technologies/",
                f"{root}/takeovers/",
                f"{root}/default-logins/",
                f"{root}/panels/",
                f"{root}/vulnerabilities/",
            ],
            "full": [
                root   # scan entire template root directory
            ]
        }.get(mode, [
            f"{root}/cves/",
            f"{root}/exposures/",
            f"{root}/misconfiguration/",
            f"{root}/technologies/",
        ])

    # -------------------------------------------------------
    # Main Execution
    # -------------------------------------------------------

    def run(self, target: str) -> str:
        cfg = getattr(self, "config", None)
        if not cfg:
            raise RuntimeError("Nuclei config missing")

        path = getattr(cfg, "path", "nuclei")
        templates_root = getattr(cfg, "templates_root", None)
        if not templates_root:
            raise RuntimeError("templates_root missing in config.yaml under tools.nuclei")

        rate_limit = getattr(cfg, "rate_limit", 50)
        concurrency = getattr(cfg, "concurrency", 25)
        timeout = getattr(cfg, "timeout", 720)
        severity = getattr(cfg, "severity", "critical,high,medium,low,info")

        target_url = self._normalize_target(target)

        # Create temporary export file
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp_json_path = tmp.name
        tmp.close()

        cmd_parts = [
            path,
            "-target", target_url,
            "-silent",
            "-td", templates_root,       # load ALL templates
            "-severity", severity,
            "-rl", str(rate_limit),
            "-c", str(concurrency),
            "-retries", "1",
            "-bulk-size", "20",
            "-timeout", "10",
            "-json-export", tmp_json_path
        ]

        cmd = " ".join(shlex.quote(p) for p in cmd_parts)

        start = time.time()
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            if os.path.exists(tmp_json_path):
                os.unlink(tmp_json_path)
            raise RuntimeError("Nuclei timed out")

        duration = time.time() - start

        # Load JSON results
        if os.path.exists(tmp_json_path):
            try:
                with open(tmp_json_path, "r") as f:
                    data = json.load(f)
                os.unlink(tmp_json_path)
                self.raw_output = json.dumps(data, indent=2)
                return self.raw_output
            except:
                if os.path.exists(tmp_json_path):
                    os.unlink(tmp_json_path)
                self.raw_output = ""
                return ""

        self.raw_output = ""
        return ""
    
    


    # -------------------------------------------------------
    # Parse JSON Export → Findings
    # -------------------------------------------------------

    def parse_output(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if not self.raw_output or self.raw_output.strip() == "" or self.raw_output.strip() == "[]":
            findings.append({
                "title": "No vulnerabilities detected",
                "description": "Nuclei ran successfully but returned zero results.",
                "severity": "info",
                "evidence": ""
            })
            return findings

        try:
            items = json.loads(self.raw_output)
        except:
            findings.append({
                "title": "Invalid JSON",
                "description": "Could not parse Nuclei JSON",
                "severity": "low",
                "evidence": self.raw_output
            })
            return findings

        if not items:
            findings.append({
                "title": "No vulnerabilities detected",
                "description": "Nuclei returned zero findings",
                "severity": "info",
                "evidence": ""
            })
            return findings

        # Convert Nuclei JSON items → Pentoolkit format
        for item in items:
            info = item.get("info", {})
            findings.append({
                "title": info.get("name", "Nuclei Finding"),
                "description": info.get("description", ""),
                "severity": info.get("severity", "info"),
                "evidence": json.dumps(item, indent=2)
            })

        return findings

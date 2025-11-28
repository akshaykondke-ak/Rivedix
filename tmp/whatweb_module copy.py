# pentoolkit/modules/whatweb_module.py
import subprocess, shlex, re
from typing import List, Dict, Any

from pentoolkit.modules.base import PentoolkitModule

class WhatWebModule(PentoolkitModule):
    name = "whatweb"
    description = "Fingerprint web technologies using WhatWeb"
    version = "1.2-python-fix"

    def run(self, target: str) -> str:
        # Python whatweb supports ONLY:  whatweb TARGET
        cmd = f"whatweb {shlex.quote(target)}"
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=20
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("WhatWeb timeout")

        self.raw_output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        return self.raw_output

    def parse_output(self) -> List[Dict[str, Any]]:
        out = self.raw_output.strip()
        findings = []

        if "error:" in out.lower() or "unrecognized arguments" in out.lower():
            findings.append({
                "title": "WhatWeb error",
                "description": "WhatWeb returned a CLI syntax error",
                "severity": "info",
                "evidence": out
            })
            return findings

        # Regex to extract plugin-style lines NAME[VALUE]
        matches = re.findall(r"([A-Za-z0-9_\-]+)\[(.*?)\]", out)

        if not matches:
            findings.append({
                "title": "WhatWeb summary",
                "description": "No fingerprint",
                "severity": "info",
                "evidence": out[:2000]
            })
            return findings

        desc = []
        for plugin, val in matches:
            desc.append(f"{plugin}: {val}")

        findings.append({
            "title": "WhatWeb fingerprint",
            "description": "; ".join(desc[:10]),   # limit noise
            "severity": "info",
            "evidence": out[:2000]
        })

        return findings



# # pentoolkit/modules/whatweb_module.py

# import subprocess
# import shlex
# import re
# from typing import Dict, Any, List

# from pentoolkit.modules.template_module import PentoolkitModule


# class WhatWebModule(PentoolkitModule):
#     name = "whatweb"
#     description = "Fingerprint web technologies using WhatWeb v0.0.8"
#     version = "0.0.8-adapter"

#     def run(self, target: str) -> str:
#         path = getattr(self.config, "path", "whatweb")
#         cmd = f"{path} {target}"

#         try:
#             proc = subprocess.run(
#                 shlex.split(cmd),
#                 capture_output=True,
#                 text=True,
#                 timeout=60
#             )
#         except subprocess.TimeoutExpired:
#             raise RuntimeError("WhatWeb timed out")

#         if proc.returncode not in [0, 1]:
#             raise RuntimeError(proc.stderr.strip())

#         self.raw_output = proc.stdout.strip()
#         return self.raw_output

#     def parse_output(self) -> List[Dict[str, Any]]:
#         out = self.raw_output.strip()
#         findings = []

#         if not out:
#             return [{
#                 "title": "Empty WhatWeb Output",
#                 "description": "No data returned by WhatWeb v0.0.8",
#                 "severity": "info",
#                 "evidence": ""
#             }]

#         # Split first line and optional "From Shodan internal DB" line
#         lines = out.split("\n")

#         main_line = lines[0]
#         shodan_line = "\n".join(lines[1:]) if len(lines) > 1 else ""

#         # 1) Parse plugin-style entries: PluginName[value]
#         matches = re.findall(r"([A-Za-z0-9\-_]+)\[([^\]]+)\]", main_line)

#         for plugin, evidence in matches:
#             sev = "info"
#             plugin_l = plugin.lower()

#             if plugin_l in ["httpserver", "meta", "title"]:
#                 sev = "info"
#             if plugin_l in ["php", "apache", "nginx", "wordpress"]:
#                 sev = "low"
#             if "old" in evidence.lower() or "outdated" in evidence.lower():
#                 sev = "medium"

#             findings.append({
#                 "title": plugin,
#                 "description": f"Detected {plugin}",
#                 "severity": sev,
#                 "evidence": evidence
#             })

#         # 2) Add Shodan fingerprint info as info finding (if exists)
#         if shodan_line.strip():
#             findings.append({
#                 "title": "Shodan Fingerprint",
#                 "description": "Additional fingerprint data from Shodan internal DB",
#                 "severity": "info",
#                 "evidence": shodan_line
#             })

#         # fallback if no plugins
#         if not findings:
#             findings.append({
#                 "title": "Raw WhatWeb Output",
#                 "description": "WhatWeb produced output but no plugins were parsed",
#                 "severity": "info",
#                 "evidence": out
#             })

#         return findings

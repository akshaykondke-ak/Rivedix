# pentoolkit/report/report_engine.py
"""
Enhanced Report Engine for Pentoolkit
Generates professional HTML reports from security scan results.
"""

import os
import json
import datetime
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

from jinja2 import Environment, FileSystemLoader, select_autoescape, Template, TemplateError

# Configure module logger
logger = logging.getLogger(__name__)

# Fallback template embedded if external file missing
FALLBACK_TEMPLATE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Pentoolkit Report</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
<div class="max-w-6xl mx-auto p-6">
  <header class="mb-6">
    <h1 class="text-3xl font-bold text-sky-700">Pentoolkit Report</h1>
    <p class="text-sm text-slate-600">Generated: {{ generated }}</p>
    {% if target %}<p class="text-sm text-slate-700">Target(s): {{ target }}</p>{% endif %}
  </header>
  <section class="grid md:grid-cols-3 gap-4 mb-6">
    <div class="p-4 bg-white rounded shadow">
      <h3 class="font-semibold">Tools</h3>
      <ul class="mt-2 text-sm text-slate-700">
        {% for t in tools %}<li>{{ t }}</li>{% endfor %}
      </ul>
    </div>
    <div class="p-4 bg-white rounded shadow">
      <h3 class="font-semibold">Totals</h3>
      <p class="mt-2 text-2xl font-bold">{{ total_findings }}</p>
    </div>
    <div class="p-4 bg-white rounded shadow">
      <h3 class="font-semibold">Severities</h3>
      <ul class="mt-2 text-sm text-slate-700">
        {% for sev,count in severities.items() %}<li class="capitalize">{{ sev }}: {{ count }}</li>{% endfor %}
      </ul>
    </div>
  </section>

  {% for tool, entries in results.items() %}
    <section class="mb-8">
      <h2 class="text-2xl font-semibold text-sky-600 mb-2">{{ tool }}</h2>
      {% for e in entries %}
        <div class="bg-white p-4 rounded shadow mb-4">
          <div class="flex justify-between items-start">
            <div>
              <div class="text-sm text-slate-500">Target: {{ e.metadata.target }}</div>
              <div class="text-lg font-semibold">{{ e.metadata.tool }}</div>
            </div>
            <div class="text-xs text-slate-500">{{ e.metadata.finished }}</div>
          </div>

          {% if e.findings %}
            <div class="mt-3 space-y-3">
              {% for f in e.findings %}
                <div class="border rounded p-3">
                  <div class="flex justify-between items-center">
                    <div class="font-semibold">{{ f.title }}</div>
                    <div class="text-sm">
                      {% if f.severity == 'critical' %}<span class="px-2 py-1 bg-red-600 text-white rounded text-xs">critical</span>
                      {% elif f.severity == 'high' %}<span class="px-2 py-1 bg-orange-500 text-white rounded text-xs">high</span>
                      {% elif f.severity == 'medium' %}<span class="px-2 py-1 bg-yellow-400 text-black rounded text-xs">medium</span>
                      {% elif f.severity == 'low' %}<span class="px-2 py-1 bg-green-400 text-black rounded text-xs">low</span>
                      {% else %}<span class="px-2 py-1 bg-gray-200 text-black rounded text-xs">info</span>{% endif %}
                    </div>
                  </div>

                  <div class="text-sm text-slate-700 mt-2">{{ f.description }}</div>

                  {% if f.evidence %}
                    <details class="mt-3">
                      <summary class="text-indigo-600 cursor-pointer text-sm">Show evidence</summary>
                      <pre class="bg-slate-100 p-3 rounded mt-2 text-xs overflow-auto">{{ f.evidence }}</pre>
                    </details>
                  {% endif %}
                </div>
              {% endfor %}
            </div>
          {% else %}
            <p class="text-sm text-slate-500 mt-3">No findings.</p>
          {% endif %}

          {% if e.raw %}
            <details class="mt-3">
              <summary class="text-slate-600 cursor-pointer text-sm">Raw output (collapsed)</summary>
              <pre class="bg-black text-white p-3 rounded mt-2 text-xs overflow-auto">{{ e.raw }}</pre>
            </details>
          {% endif %}
        </div>
      {% endfor %}
    </section>
  {% endfor %}
</div>
</body>
</html>
"""


class ReportEngine:
    """
    Enhanced report generation engine for penetration testing results.
    
    Features:
    - Template-based HTML report generation
    - Automatic severity tracking and statistics
    - Fallback template support
    - Comprehensive error handling
    - Type-safe operations
    """
    
    # Valid severity levels
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    
    def __init__(
        self, 
        template_path: Optional[str] = None, 
        output_dir: str = "results"
    ):
        """
        Initialize the report engine.
        
        Args:
            template_path: Path to custom Jinja2 template file
            output_dir: Directory for output reports
        """
        self.template_path = template_path
        self.output_dir = output_dir
        self.results: Dict[str, List[Dict[str, Any]]] = {}
        self.tools: Set[str] = set()
        
        # Ensure output directory exists
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.info(f"Report output directory: {self.output_dir}")
        except OSError as e:
            logger.error(f"Failed to create output directory '{self.output_dir}': {e}")
            raise
        
        # Validate template path if provided
        if self.template_path and not os.path.exists(self.template_path):
            logger.warning(
                f"Template path '{self.template_path}' does not exist. "
                "Will use fallback template."
            )

    def add_run_result(
        self, 
        tool_name: str, 
        results: List[Dict[str, Any]]
    ) -> None:
        """
        Add scan results for a specific tool.
        
        Args:
            tool_name: Name of the security tool
            results: List of result dictionaries containing findings
        """
        if not tool_name:
            logger.warning("Tool name is empty, skipping add_run_result")
            return
        
        if not isinstance(results, list):
            logger.error(f"Results for '{tool_name}' must be a list, got {type(results)}")
            return
        
        # Validate and sanitize results
        validated_results = self._validate_results(results, tool_name)
        
        self.results[tool_name] = validated_results
        self.tools.add(tool_name)
        
        findings_count = sum(len(r.get("findings", [])) for r in validated_results)
        logger.info(
            f"Added results for tool '{tool_name}': "
            f"{len(validated_results)} entries, {findings_count} findings"
        )

    def _validate_results(
        self, 
        results: List[Dict[str, Any]], 
        tool_name: str
    ) -> List[Dict[str, Any]]:
        """
        Validate and sanitize result entries.
        
        Args:
            results: Raw results list
            tool_name: Tool name for logging
            
        Returns:
            Validated results list
        """
        validated = []
        
        for idx, entry in enumerate(results):
            if not isinstance(entry, dict):
                logger.warning(
                    f"Tool '{tool_name}' entry {idx} is not a dict, skipping"
                )
                continue
            
            # Ensure required structure
            if "metadata" not in entry:
                entry["metadata"] = {}
            if "findings" not in entry:
                entry["findings"] = []
            
            # Validate findings
            validated_findings = []
            for finding in entry.get("findings", []):
                if isinstance(finding, dict):
                    # Normalize severity
                    severity = finding.get("severity", "info").lower()
                    if severity not in self.VALID_SEVERITIES:
                        logger.debug(
                            f"Invalid severity '{severity}' in {tool_name}, "
                            f"defaulting to 'info'"
                        )
                        finding["severity"] = "info"
                    else:
                        finding["severity"] = severity
                    
                    validated_findings.append(finding)
            
            entry["findings"] = validated_findings
            validated.append(entry)
        
        return validated

    def _compute_severity_counts(self) -> Dict[str, int]:
        """
        Calculate count of findings by severity level.
        
        Returns:
            Dictionary mapping severity levels to counts
        """
        counts = defaultdict(int, {sev: 0 for sev in self.VALID_SEVERITIES})
        
        for tool_name, entries in self.results.items():
            for entry in entries:
                for finding in entry.get("findings", []):
                    severity = finding.get("severity", "info")
                    counts[severity] += 1
        
        # Convert back to regular dict for template
        return dict(counts)

    def _load_template(self) -> Template:
        """
        Load Jinja2 template from file or use fallback.
        
        Returns:
            Compiled Jinja2 template
            
        Raises:
            TemplateError: If template loading fails critically
        """
        if self.template_path and os.path.exists(self.template_path):
            try:
                template_dir = os.path.dirname(os.path.abspath(self.template_path))
                template_file = os.path.basename(self.template_path)
                
                env = Environment(
                    loader=FileSystemLoader(template_dir),
                    autoescape=select_autoescape(['html', 'xml'])
                )
                
                template = env.get_template(template_file)
                logger.info(f"Loaded template from: {self.template_path}")
                return template
                
            except TemplateError as e:
                logger.error(f"Failed to load template '{self.template_path}': {e}")
                logger.info("Falling back to embedded template")
        
        # Use fallback template
        logger.debug("Using embedded fallback template")
        return Template(FALLBACK_TEMPLATE, autoescape=select_autoescape(['html', 'xml']))

    def generate_html(
        self, 
        run_id: str, 
        output_filename: Optional[str] = None, 
        target: Optional[str] = None
    ) -> str:
        """
        Generate HTML report from collected results.
        
        Args:
            run_id: Unique identifier for this scan run
            output_filename: Custom output path (optional)
            target: Target system/URL being scanned (optional)
            
        Returns:
            Path to generated HTML report
            
        Raises:
            IOError: If report file cannot be written
            TemplateError: If template rendering fails
        """
        if not run_id:
            raise ValueError("run_id cannot be empty")
        
        logger.info(f"Generating report for run_id: {run_id}")
        
        # Load template
        try:
            template = self._load_template()
        except Exception as e:
            logger.critical(f"Failed to load any template: {e}")
            raise
        
        # Calculate statistics
        total_findings = sum(
            len(entry.get("findings", [])) 
            for entries in self.results.values() 
            for entry in entries
        )
        severities = self._compute_severity_counts()
        
        logger.debug(
            f"Report statistics: {total_findings} total findings, "
            f"severity breakdown: {severities}"
        )
        
        # Prepare template context
        context = {
            "generated": datetime.datetime.utcnow().isoformat(),
            "results": self.results,
            "tools": sorted(list(self.tools)),
            "total_findings": total_findings,
            "severities": severities,
            "target": target or "N/A",
            "run": run_id
        }
        
        # Render template
        try:
            rendered = template.render(**context)
        except TemplateError as e:
            logger.error(f"Template rendering failed: {e}")
            raise
        
        # Determine output path
        if not output_filename:
            # Sanitize run_id for filename
            safe_run_id = "".join(
                c if c.isalnum() or c in "-_" else "_" 
                for c in run_id
            )
            output_filename = os.path.join(
                self.output_dir, 
                f"{safe_run_id}__report.html"
            )
        
        # Write report file
        try:
            with open(output_filename, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            
            file_size = os.path.getsize(output_filename)
            logger.info(
                f"Report generated successfully: {output_filename} "
                f"({file_size:,} bytes)"
            )
            
        except IOError as e:
            logger.error(f"Failed to write report file '{output_filename}': {e}")
            raise
        
        return output_filename

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of collected results.
        
        Returns:
            Dictionary with summary information
        """
        total_findings = sum(
            len(entry.get("findings", [])) 
            for entries in self.results.values() 
            for entry in entries
        )
        
        return {
            "total_tools": len(self.tools),
            "total_entries": sum(len(entries) for entries in self.results.values()),
            "total_findings": total_findings,
            "severities": self._compute_severity_counts(),
            "tools": sorted(list(self.tools))
        }

    def clear_results(self) -> None:
        """Clear all stored results and reset the engine."""
        self.results.clear()
        self.tools.clear()
        logger.info("Cleared all results from report engine")

    def export_json(self, output_path: str) -> str:
        """
        Export results as JSON file.
        
        Args:
            output_path: Path for JSON output
            
        Returns:
            Path to exported JSON file
        """
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "results": self.results,
                        "summary": self.get_summary(),
                        "generated": datetime.datetime.utcnow().isoformat()
                    },
                    fh,
                    indent=2,
                    ensure_ascii=False
                )
            
            logger.info(f"Exported results to JSON: {output_path}")
            return output_path
            
        except IOError as e:
            logger.error(f"Failed to export JSON to '{output_path}': {e}")
            raise


# Convenience function for quick report generation
def generate_quick_report(
    results_dict: Dict[str, List[Dict[str, Any]]],
    run_id: str,
    output_dir: str = "results",
    target: Optional[str] = None,
    template_path: Optional[str] = None
) -> str:
    """
    Quick report generation from results dictionary.
    
    Args:
        results_dict: Dictionary of tool results
        run_id: Run identifier
        output_dir: Output directory
        target: Target system
        template_path: Custom template path
        
    Returns:
        Path to generated report
    """
    engine = ReportEngine(template_path=template_path, output_dir=output_dir)
    
    for tool_name, results in results_dict.items():
        engine.add_run_result(tool_name, results)
    
    return engine.generate_html(run_id=run_id, target=target)
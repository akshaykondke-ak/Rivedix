# pentoolkit/report/report_engine.py
import os
import json
import datetime
from typing import Dict, List, Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape, Template

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

  {% if tool == "subfinder" %}
    <!-- ========================== -->
    <!-- SPECIAL RENDER FOR SUBFINDER -->
    <!-- ========================== -->

    <article class="bg-white p-6 rounded shadow mb-6">

      <!-- Header -->
      <div class="flex justify-between items-start">
        <div>
          <p class="text-sm text-slate-600">Target: {{ e.metadata.target }}</p>
          <p class="text-lg font-medium">{{ e.metadata.tool }}</p>
        </div>
        <p class="text-xs text-slate-500">{{ e.metadata.finished }}</p>
      </div>

      <h3 class="text-xl font-semibold mt-4 text-sky-700">Subdomain Enumeration</h3>

      <p class="text-sm text-slate-600 mt-1">
        Total Subdomains: {{ e.findings | length - 1 }}
      </p>

      <!-- FIRST 20 SUBDOMAINS IN TABLE -->
      <div class="overflow-auto max-h-64 border rounded mt-4">
        <table class="w-full text-sm">
          <thead class="bg-slate-100 text-slate-700 sticky top-0">
            <tr>
              <th class="p-2 text-left">Subdomain</th>
            </tr>
          </thead>
          <tbody>
            {% for f in e.findings[:20] %}
              {% if f.title == "Subdomain Found" %}
                <tr class="border-b">
                  <td class="p-2">{{ f.evidence }}</td>
                </tr>
              {% endif %}
            {% endfor %}
          </tbody>
        </table>
      </div>

      <!-- COLLAPSIBLE FULL LIST -->
      <details class="mt-4">
        <summary class="cursor-pointer text-indigo-600 text-sm">
          Show all {{ e.findings | length - 1 }} subdomains
        </summary>

        <pre class="bg-slate-100 text-xs p-3 rounded mt-2 overflow-auto max-h-72">
{% for f in e.findings %}
  {% if f.title == "Subdomain Found" %}
{{ f.evidence }}
  {% endif %}
{% endfor %}
        </pre>
      </details>

      {% if e.raw %}
        <details class="mt-4">
          <summary class="text-indigo-700 cursor-pointer text-sm">Raw Output</summary>
          <pre class="bg-black text-white text-xs mt-2 p-3 rounded overflow-auto">{{ e.raw | e }}</pre>
        </details>
      {% endif %}

    </article>

  {% else %}
    <!-- ========================== -->
    <!-- NORMAL TOOL RENDERING -->
    <!-- ========================== -->

    <article class="bg-white p-6 rounded shadow mb-6">
      <div class="flex justify-between items-start">
        <div>
          <p class="text-sm text-slate-600">Target: {{ e.metadata.target }}</p>
          <p class="text-lg font-medium">{{ e.metadata.tool }}</p>
        </div>
        <p class="text-xs text-slate-500">{{ e.metadata.finished }}</p>
      </div>

      {% if e.findings %}
        <div class="mt-4 space-y-4">
          {% for f in e.findings %}
            <div class="p-4 border rounded">
              <div class="flex justify-between items-center">
                <span class="font-semibold">{{ f.title }}</span>

                {% if f.severity == 'critical' %}
                  <span class="px-2 py-1 bg-red-600 text-white rounded text-xs">critical</span>
                {% elif f.severity == 'high' %}
                  <span class="px-2 py-1 bg-orange-600 text-white rounded text-xs">high</span>
                {% elif f.severity == 'medium' %}
                  <span class="px-2 py-1 bg-yellow-400 text-black rounded text-xs">medium</span>
                {% elif f.severity == 'low' %}
                  <span class="px-2 py-1 bg-green-500 text-black rounded text-xs">low</span>
                {% else %}
                  <span class="px-2 py-1 bg-gray-300 text-black rounded text-xs">info</span>
                {% endif %}
              </div>

              <p class="text-sm text-slate-700 mt-2">{{ f.description }}</p>

              {% if f.evidence %}
                <details class="mt-3">
                  <summary class="text-sky-700 cursor-pointer text-sm">Show Evidence</summary>
                  <pre class="bg-slate-100 text-xs mt-2 p-3 rounded overflow-auto">{{ f.evidence | e }}</pre>
                </details>
              {% endif %}
            </div>
          {% endfor %}
        </div>
      {% else %}
        <p class="text-sm mt-3 text-slate-500">No findings.</p>
      {% endif %}

      {% if e.raw %}
        <details class="mt-4">
          <summary class="text-indigo-700 cursor-pointer text-sm">Raw Output</summary>
          <pre class="bg-black text-white text-xs mt-2 p-3 rounded overflow-auto">{{ e.raw | e }}</pre>
        </details>
      {% endif %}
    </article>

  {% endif %}

{% endfor %}

    </section>
  {% endfor %}
</div>
</body>
</html>
"""

class ReportEngine:
    def __init__(self, template_path: Optional[str] = None, output_dir: str = "results"):
        self.template_path = template_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.results: Dict[str, List[Dict[str, Any]]] = {}
        self.tools = set()

    def add_run_result(self, tool_name: str, results: List[Dict[str, Any]]):
        self.results[tool_name] = results
        self.tools.add(tool_name)

    def _compute_severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for tool, entries in self.results.items():
            for e in entries:
                for f in e.get("findings", []):
                    sev = f.get("severity", "info")
                    counts[sev] = counts.get(sev, 0) + 1
        return counts

    def generate_html(self, run_id: str, output_filename: Optional[str] = None, target: Optional[str] = None):
        # choose template
        if self.template_path and os.path.exists(self.template_path):
            env = Environment(loader=FileSystemLoader(os.path.dirname(self.template_path)), autoescape=select_autoescape())
            tpl = env.get_template(os.path.basename(self.template_path))
        else:
            tpl = Template(FALLBACK_TEMPLATE)

        total_findings = sum(len(e.get("findings", [])) for entries in self.results.values() for e in entries)
        severities = self._compute_severity_counts()

        rendered = tpl.render(
            generated=datetime.datetime.utcnow().isoformat(),
            results=self.results,
            tools=sorted(list(self.tools)),
            total_findings=total_findings,
            severities=severities,
            target=target,
            run=run_id
        )

        if not output_filename:
            output_filename = os.path.join(self.output_dir, f"{run_id}__report.html")
        with open(output_filename, "w", encoding="utf-8") as fh:
            fh.write(rendered)

        return output_filename

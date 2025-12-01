"""
Enhanced Pentoolkit CLI with real-time progress, interactive mode, and better UX.
Replace your current cli.py with this file.
"""

from __future__ import annotations

import json
import os
import sys
import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskID
)
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from pentoolkit.config import ConfigLoader
from pentoolkit.runner import Runner
from pentoolkit.report.report_engine import ReportEngine
from pentoolkit.utils.logging import init_logging, get_logger


# ============================================================================
# CLI APP INITIALIZATION
# ============================================================================

app = typer.Typer(
    help="Pentoolkit – Professional Security Scanning Framework",
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()
logger = get_logger("pentoolkit.cli")

RESULTS_DIR = "results/runs/"


# ============================================================================
# SCAN TEMPLATES (Predefined Configurations)
# ============================================================================

SCAN_TEMPLATES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast reconnaissance (httpx + nmap short)",
        "tools": ["httpx", "nmap"],
        "nmap_type": "short"
    },
    "standard": {
        "name": "Standard Scan",
        "description": "Comprehensive scan (all tools, medium depth)",
        "tools": ["httpx", "nmap", "subfinder", "tlsinfo", "whatweb", "nuclei"],
        "nmap_type": "fast"
    },
    "deep": {
        "name": "Deep Scan",
        "description": "Thorough analysis (all tools, maximum depth)",
        "tools": ["httpx", "nmap", "subfinder", "tlsinfo", "whatweb", "nuclei"],
        "nmap_type": "deep"
    },
    "web": {
        "name": "Web Application Scan",
        "description": "Web-focused testing (httpx + nuclei + whatweb)",
        "tools": ["httpx", "whatweb", "nuclei"],
        "nmap_type": None
    },
    "network": {
        "name": "Network Scan",
        "description": "Network reconnaissance (nmap + tlsinfo)",
        "tools": ["nmap", "tlsinfo"],
        "nmap_type": "deep"
    }
}


# ============================================================================
# ENHANCED PROGRESS TRACKING
# ============================================================================

class ScanProgressTracker:
    """
    Real-time progress tracker for scans with per-tool status.
    """
    
    def __init__(self, tools: List[str], targets: List[str]):
        self.tools = tools
        self.targets = targets
        self.tool_status: Dict[str, str] = {tool: "pending" for tool in tools}
        self.tool_findings: Dict[str, int] = {tool: 0 for tool in tools}
        self.current_tool: Optional[str] = None
    
    def start_tool(self, tool: str):
        """Mark tool as running."""
        self.current_tool = tool
        self.tool_status[tool] = "running"
    
    def finish_tool(self, tool: str, findings_count: int):
        """Mark tool as complete."""
        self.tool_status[tool] = "complete"
        self.tool_findings[tool] = findings_count
        self.current_tool = None
    
    def fail_tool(self, tool: str):
        """Mark tool as failed."""
        self.tool_status[tool] = "failed"
        self.current_tool = None
    
    def get_status_emoji(self, tool: str) -> str:
        """Get emoji for tool status."""
        status = self.tool_status.get(tool, "pending")
        return {
            "pending": "⏳",
            "running": "🔄",
            "complete": "✅",
            "failed": "❌"
        }.get(status, "❓")
    
    def render_status_table(self) -> Table:
        """Render current status as Rich table."""
        table = Table(title="Scan Progress", show_header=True, header_style="bold magenta")
        table.add_column("Tool", style="cyan", width=15)
        table.add_column("Status", width=10)
        table.add_column("Findings", justify="right", style="green")
        
        for tool in self.tools:
            emoji = self.get_status_emoji(tool)
            status = self.tool_status[tool]
            findings = self.tool_findings[tool]
            
            status_text = f"{emoji} {status.capitalize()}"
            findings_text = str(findings) if status == "complete" else "-"
            
            table.add_row(tool, status_text, findings_text)
        
        return table


# ============================================================================
# HELPERS
# ============================================================================

def _format_run_id(targets: List[str]) -> str:
    """Generate run ID from timestamp and targets."""
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    if len(targets) == 1:
        name = targets[0].replace("https://", "").replace("http://", "")
        name = name.replace("/", "_")[:50]  # Limit length
        return f"{timestamp}_{name}"
    return f"{timestamp}_multi"


def _save_results_into_run_folder(
    run_id: str,
    all_results: Dict[str, List[Any]],
    targets: List[str]
) -> str:
    """Save scan results to run folder."""
    base_dir = Path(RESULTS_DIR) / run_id
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Save individual tool results
    for tool_name, data in all_results.items():
        tool_file = base_dir / f"{tool_name}.json"
        with open(tool_file, "w") as f:
            json.dump(data, f, indent=2)
    
    # Save metadata
    meta = {
        "run_id": run_id,
        "targets": targets,
        "tools": list(all_results.keys()),
        "timestamp": run_id.split("_")[0],
        "total_findings": sum(
            len(r.get("findings", []))
            for results in all_results.values()
            for r in results
        )
    }
    
    meta_file = base_dir / "meta.json"
    with open(meta_file, "w") as f:
        json.dump(meta, f, indent=2)
    
    return str(base_dir)


def _print_scan_summary(all_results: Dict[str, List[Any]], run_id: str, run_dir: str):
    """Print beautiful scan summary."""
    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_findings = 0
    
    for tool_results in all_results.values():
        for result in tool_results:
            for finding in result.get("findings", []):
                sev = finding.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                total_findings += 1
    
    # Create summary panel
    summary_text = f"""
[bold cyan]Scan Complete![/bold cyan]
[white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/white]

[bold]Run ID:[/bold] {run_id}
[bold]Tools Executed:[/bold] {len(all_results)}
[bold]Total Findings:[/bold] {total_findings}

[bold red]Critical:[/bold red] {severity_counts['critical']}
[bold yellow]High:[/bold yellow] {severity_counts['high']}
[bold blue]Medium:[/bold blue] {severity_counts['medium']}
[bold green]Low:[/bold green] {severity_counts['low']}
[bold white]Info:[/bold white] {severity_counts['info']}

[bold]Results saved to:[/bold]
{run_dir}

[bold cyan]Generate Report:[/bold cyan]
pentoolkit report --run {run_id}
"""
    
    console.print(Panel(summary_text, title="✨ Scan Summary ✨", border_style="green"))


# ============================================================================
# COMMANDS
# ============================================================================

@app.command("scan")
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single target to scan"),
    targets_file: Optional[str] = typer.Option(None, "--targets-file", "-f", help="File with targets (one per line)"),
    tool: Optional[str] = typer.Option(None, "--tool", help="Specific tool to run"),
    all_tools: bool = typer.Option(False, "--all", help="Run all enabled tools"),
    template: Optional[str] = typer.Option(None, "--template", help=f"Scan template: {', '.join(SCAN_TEMPLATES.keys())}"),
    scan_type: Optional[str] = typer.Option(None, "--type", "-p", help="Nmap scan type"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-c", help="Concurrent tool executions"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive mode"),
    skip_report: bool = typer.Option(False, "--skip-report", help="Skip automatic report generation")
):
    """
    Execute security scans on target(s).
    
    Examples:
        # Quick scan on single target
        pentoolkit scan -t example.com --template quick
        
        # Interactive mode (guided setup)
        pentoolkit scan --interactive
        
        # Run specific tool
        pentoolkit scan -t example.com --tool nmap --type deep
        
        # Run all tools on multiple targets
        pentoolkit scan -f targets.txt --all
    """
    # Initialize logging
    init_logging(log_level="INFO")
    
    # Interactive mode
    if interactive:
        return _interactive_scan()
    
    # Load configuration
    try:
        # Get config path relative to project root
        import os
        project_root = Path(__file__).parent.parent
        config_path = project_root / "config.yaml"
        
        if not config_path.exists():
            console.print(f"[red]Config not found:[/red] {config_path}")
            console.print(f"[yellow]Looking in:[/yellow] {project_root}")
            raise typer.Exit(1)
        
        cfg_loader = ConfigLoader(str(config_path))
        cfg_loader.load()
        runner = Runner(str(config_path))
    except Exception as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        raise typer.Exit(1)
    
    # Set concurrency if provided
    if concurrency:
        runner.global_cfg.concurrency = concurrency
    
    # ===== COLLECT TARGETS =====
    targets = []
    
    if target:
        targets.append(target.strip())
    
    if targets_file:
        try:
            with open(targets_file, "r") as f:
                targets.extend([ln.strip() for ln in f if ln.strip()])
        except FileNotFoundError:
            console.print(f"[red]Targets file not found:[/red] {targets_file}")
            raise typer.Exit(1)
    
    if not targets:
        console.print("[yellow]No targets provided.[/yellow]")
        user_input = Prompt.ask("Enter target(s) (comma-separated)")
        targets = [t.strip() for t in user_input.split(",")]
    
    # ===== DETERMINE TOOLS TO RUN =====
    tools_to_run = []
    
    if template:
        # Use scan template
        if template not in SCAN_TEMPLATES:
            console.print(f"[red]Unknown template:[/red] {template}")
            console.print(f"Available: {', '.join(SCAN_TEMPLATES.keys())}")
            raise typer.Exit(1)
        
        tpl = SCAN_TEMPLATES[template]
        tools_to_run = tpl["tools"]
        scan_type = scan_type or tpl.get("nmap_type")
        
        console.print(f"[cyan]Using template:[/cyan] {tpl['name']} - {tpl['description']}")
    
    elif all_tools:
        tools_to_run = runner.config_loader.get_enabled_tools()
    
    elif tool:
        tools_to_run = [tool]
    
    else:
        console.print("[yellow]No tools specified. Use --tool, --all, or --template[/yellow]")
        raise typer.Exit(1)
    
    # Set scan type for nmap
    if scan_type:
        runner.selected_scan_type = scan_type
    
    # ===== EXECUTE SCAN =====
    run_id = _format_run_id(targets)
    
    console.print(f"\n[bold cyan]Starting scan:[/bold cyan] {run_id}")
    console.print(f"[bold]Targets:[/bold] {', '.join(targets)}")
    console.print(f"[bold]Tools:[/bold] {', '.join(tools_to_run)}\n")
    
    # Create progress tracker
    tracker = ScanProgressTracker(tools_to_run, targets)
    
    all_results = {}
    
    # Execute with live progress display
    with Live(tracker.render_status_table(), refresh_per_second=4, console=console) as live:
        for tool_name in tools_to_run:
            try:
                tracker.start_tool(tool_name)
                live.update(tracker.render_status_table())
                
                logger.info(f"Starting {tool_name} on {len(targets)} target(s)")
                
                # Execute tool
                tool_results = runner.execute_tool_multi(tool_name, targets)
                
                # Count findings
                findings_count = sum(len(r.get("findings", [])) for r in tool_results)
                
                tracker.finish_tool(tool_name, findings_count)
                all_results[tool_name] = tool_results
                
                live.update(tracker.render_status_table())
                
            except Exception as e:
                logger.error(f"Tool {tool_name} failed: {e}", exc_info=True)
                tracker.fail_tool(tool_name)
                all_results[tool_name] = []
                live.update(tracker.render_status_table())
    
    # ===== SAVE RESULTS =====
    run_dir = _save_results_into_run_folder(run_id, all_results, targets)
    
    # ===== GENERATE REPORT (optional) =====
    if not skip_report:
        try:
            console.print("\n[cyan]Generating report...[/cyan]")
            _generate_report_for_run(run_id, run_dir, all_results)
        except Exception as e:
            console.print(f"[yellow]Report generation failed:[/yellow] {e}")
    
    # ===== PRINT SUMMARY =====
    _print_scan_summary(all_results, run_id, run_dir)


def _interactive_scan():
    """Interactive mode for guided scan setup."""
    console.print(Panel(
        "[bold cyan]Interactive Scan Mode[/bold cyan]\n"
        "Let's configure your scan step by step.",
        title="🔍 Pentoolkit",
        border_style="cyan"
    ))
    
    # Step 1: Target
    console.print("\n[bold]Step 1: Target Selection[/bold]")
    target_mode = Prompt.ask(
        "How do you want to provide targets?",
        choices=["single", "multiple", "file"],
        default="single"
    )
    
    targets = []
    if target_mode == "single":
        target = Prompt.ask("Enter target (IP/domain/URL)")
        targets = [target]
    elif target_mode == "multiple":
        target_input = Prompt.ask("Enter targets (comma-separated)")
        targets = [t.strip() for t in target_input.split(",")]
    else:  # file
        filepath = Prompt.ask("Enter targets file path")
        with open(filepath, "r") as f:
            targets = [ln.strip() for ln in f if ln.strip()]
    
    # Step 2: Scan template
    console.print("\n[bold]Step 2: Scan Configuration[/bold]")
    console.print("Available templates:")
    for key, tpl in SCAN_TEMPLATES.items():
        console.print(f"  [cyan]{key}[/cyan]: {tpl['description']}")
    
    template = Prompt.ask(
        "Choose scan template",
        choices=list(SCAN_TEMPLATES.keys()),
        default="standard"
    )
    
    # Step 3: Confirm
    console.print("\n[bold]Step 3: Review Configuration[/bold]")
    console.print(f"[bold]Targets:[/bold] {', '.join(targets)}")
    console.print(f"[bold]Template:[/bold] {SCAN_TEMPLATES[template]['name']}")
    console.print(f"[bold]Tools:[/bold] {', '.join(SCAN_TEMPLATES[template]['tools'])}")
    
    if not Confirm.ask("\nProceed with scan?", default=True):
        console.print("[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(0)
    
    # Execute with template
    ctx = typer.Context(scan)
    ctx.invoke(
        scan,
        target=None,
        targets_file=None,
        template=template,
        all_tools=False,
        tool=None,
        interactive=False
    )


def _generate_report_for_run(run_id: str, run_dir: str, all_results: Dict[str, List[Any]]):
    """Generate HTML report for a run."""
    template_path = Path(__file__).parent / "report" / "templates" / "report.html"
    
    engine = ReportEngine(template_path=str(template_path))
    
    for tool_name, results in all_results.items():
        engine.add_run_result(tool_name, results)
    
    output_path = Path(run_dir) / "report.html"
    
    # Extract targets from first result
    targets = []
    for results in all_results.values():
        for result in results:
            target = result.get("metadata", {}).get("target")
            if target and target not in targets:
                targets.append(target)
    
    engine.generate_html(
        run_id,
        output_filename=str(output_path),
        target=", ".join(targets)
    )
    
    console.print(f"[green]Report generated:[/green] {output_path}")


@app.command("report")
def report(run: str = typer.Option(..., "--run", help="Run ID to generate report for")):
    """
    Generate HTML report for a completed scan.
    
    Example:
        pentoolkit report --run 20241127_example.com
    """
    run_folder = Path(RESULTS_DIR) / run
    
    if not run_folder.exists():
        console.print(f"[red]Run folder not found:[/red] {run}")
        raise typer.Exit(1)
    
    # Load results
    results = {}
    for file in run_folder.glob("*.json"):
        if file.name != "meta.json":
            tool_name = file.stem
            with open(file) as f:
                results[tool_name] = json.load(f)
    
    # Load metadata
    meta_file = run_folder / "meta.json"
    with open(meta_file) as f:
        meta = json.load(f)
    
    # Generate report
    template_path = Path(__file__).parent / "report" / "templates" / "report.html"
    engine = ReportEngine(template_path=str(template_path))
    
    for tool, data in results.items():
        engine.add_run_result(tool, data)
    
    output_path = run_folder / "report.html"
    engine.generate_html(
        run,
        output_filename=str(output_path),
        target=", ".join(meta.get("targets", []))
    )
    
    console.print(f"[green]Report generated successfully:[/green] {output_path}")


@app.command("list-modules")
def list_modules():
    """List all available security scanning modules."""
    runner = Runner()
    modules = runner.registry.list_modules()
    
    table = Table(title="Available Modules", show_header=True, header_style="bold magenta")
    table.add_column("Module", style="cyan", width=15)
    table.add_column("Description", width=50)
    table.add_column("Status", width=10)
    
    for name in sorted(modules):
        cls = runner.registry.get(name)
        inst = cls(config=None, logger=None)
        
        # Check if enabled in config
        try:
            cfg = runner.config_loader.tool(name)
            status = "✅ Enabled" if cfg.enabled else "❌ Disabled"
        except KeyError:
            status = "⚠️ No config"
        
        table.add_row(name, inst.description, status)
    
    console.print(table)


@app.command("list-runs")
def list_runs(limit: int = typer.Option(20, "--limit", "-n", help="Number of recent runs to show")):
    """List recent scan runs."""
    runs_dir = Path(RESULTS_DIR)
    
    if not runs_dir.exists():
        console.print("[yellow]No runs yet.[/yellow]")
        raise typer.Exit()
    
    runs = sorted(runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    
    if not runs:
        console.print("[yellow]No runs found.[/yellow]")
        raise typer.Exit()
    
    table = Table(title=f"Recent Scans (Last {len(runs)})", show_header=True)
    table.add_column("Run ID", style="green", width=30)
    table.add_column("Targets", width=25)
    table.add_column("Tools", width=15)
    table.add_column("Findings", justify="right", style="cyan")
    table.add_column("Date", style="yellow")
    
    for run_dir in runs:
        meta_file = run_dir / "meta.json"
        if not meta_file.exists():
            continue
        
        with open(meta_file) as f:
            meta = json.load(f)
        
        run_id = run_dir.name
        targets_str = ", ".join(meta.get("targets", [])[:2])
        if len(meta.get("targets", [])) > 2:
            targets_str += f" +{len(meta['targets']) - 2} more"
        
        tools_count = len(meta.get("tools", []))
        findings_count = meta.get("total_findings", "-")
        
        # Parse timestamp
        timestamp_str = meta.get("timestamp", "")
        try:
            dt = datetime.datetime.strptime(timestamp_str, "%Y%m%dT%H%M%SZ")
            date_str = dt.strftime("%Y-%m-%d %H:%M")
        except:
            date_str = timestamp_str[:8]
        
        table.add_row(run_id, targets_str, f"{tools_count} tools", str(findings_count), date_str)
    
    console.print(table)


@app.command("templates")
def templates():
    """Show available scan templates."""
    table = Table(title="Scan Templates", show_header=True)
    table.add_column("Template", style="cyan", width=12)
    table.add_column("Name", style="bold", width=20)
    table.add_column("Description", width=40)
    table.add_column("Tools", width=30)
    
    for key, tpl in SCAN_TEMPLATES.items():
        tools_str = ", ".join(tpl["tools"][:3])
        if len(tpl["tools"]) > 3:
            tools_str += f" +{len(tpl['tools']) - 3}"
        
        table.add_row(key, tpl["name"], tpl["description"], tools_str)
    
    console.print(table)
    console.print("\n[bold]Usage:[/bold] pentoolkit scan -t example.com --template <template_name>")


def main():
    """Main entry point."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal error:[/red] {e}")
        logger.exception("Fatal error in CLI")
        sys.exit(1)


if __name__ == "__main__":
    main()
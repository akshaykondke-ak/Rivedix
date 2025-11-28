from __future__ import annotations

import json
import os
import sys
import datetime
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn

from pentoolkit.config import ConfigLoader
from pentoolkit.runner import Runner
from pentoolkit.report.report_engine import ReportEngine
# In cli.py, add at the top of main():
from pentoolkit.utils.logging import init_logging
   
def main():
    init_logging(log_level="INFO")
    app()

app = typer.Typer(help="Pentoolkit — Interactive Security Toolkit")
console = Console()

RESULTS_DIR = "results/runs/"


# -----------------------------------------------------------
# Helpers
# -----------------------------------------------------------

def _format_run_id(targets: List[str]) -> str:
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    if len(targets) == 1:
        name = targets[0].replace("https://", "").replace("http://", "")
        name = name.replace("/", "_")
        return f"{timestamp}_{name}"
    return f"{timestamp}_multi"


def _save_results_into_run_folder(run_id: str, all_results: dict, targets: List[str]) -> str:
    base_dir = os.path.join(RESULTS_DIR, run_id)
    os.makedirs(base_dir, exist_ok=True)

    # individual tool JSON output
    for tool_name, data in all_results.items():
        with open(os.path.join(base_dir, f"{tool_name}.json"), "w") as f:
            json.dump(data, f, indent=2)

    meta = {
        "run_id": run_id,
        "targets": targets,
        "tools": list(all_results.keys()),
        "timestamp": run_id.split("_")[0]
    }
    with open(os.path.join(base_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    return base_dir


# helper: utility to join ports/services
def _format_ports(ports_list):
    if not ports_list:
        return "-"
    return ", ".join(ports_list)

def _format_services(services_list):
    if not services_list:
        return "-"
    # each service can be "80/tcp -> http (nginx 1.2.3)"
    return "\n".join(services_list)

# Generic fallback pretty printer
def _print_generic(results, tool_name):
    table = Table(title=f"{tool_name.upper()} Results")
    table.add_column("Target")
    table.add_column("Findings", justify="right")
    table.add_column("Top Severity", justify="center")
    for r in results:
        target = r.get("metadata", {}).get("target", "unknown")
        findings = r.get("findings", [])
        count = str(len(findings))
        top = "-"
        for s in ["critical","high","medium","low","info"]:
            if any((f.get("severity")==s) for f in findings):
                top = s
                break
        table.add_row(target, count, top)
    console.print(table)

# Nmap-friendly printer
def _print_nmap(results, tool_name="nmap"):
    table = Table(title="NMAP Results")
    table.add_column("Target")
    table.add_column("Open Ports")
    table.add_column("Services")
    table.add_column("Findings", justify="right")
    table.add_column("Severity", justify="center")
    table.add_column("Summary")
    for r in results:
        meta = r.get("metadata", {})
        findings = r.get("findings", [])
        raw = r.get("raw", "")
        # collect open ports and services from findings or parsed metadata
        open_ports = meta.get("open_ports") or []
        services = meta.get("services") or []

        # string formats
        ports_s = _format_ports(open_ports)
        services_s = _format_services(services)

        # severity
        top = "-"
        for s in ["critical","high","medium","low","info"]:
            if any((f.get("severity")==s) for f in findings):
                top = s
                break

        # simple summary heuristic
        summary = "No Risk" if top in ("info", "-") else ("Review" if top=="medium" else top.upper())

        table.add_row(
            meta.get("target", "unknown"),
            ports_s,
            services_s,
            str(len(findings)),
            top,
            summary
        )
    console.print(table)

# httpx printer
def _print_httpx(results, tool_name="httpx"):
    table = Table(title="HTTPX Results")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Tech")
    table.add_column("Findings", justify="right")
    for r in results:
        meta = r.get("metadata", {})
        findings = r.get("findings", [])
        http = meta.get("http", {}) or {}
        status = http.get("status","-")
        title = http.get("title","-")
        tech = ", ".join(http.get("tech", [])) if http.get("tech") else "-"
        table.add_row(meta.get("target","-"), str(status), title, tech, str(len(findings)))
    console.print(table)

# TLS printer
def _print_tlsinfo(results, tool_name="tlsinfo"):
    table = Table(title="TLSINFO Results")
    table.add_column("Target")
    table.add_column("Protocols")
    table.add_column("Issuer")
    table.add_column("Expiry")
    table.add_column("Findings", justify="right")
    for r in results:
        meta = r.get("metadata", {})
        tls = meta.get("tls", {}) or {}
        protocols = tls.get("protocols", "-")
        issuer = tls.get("issuer", "-")
        expiry = tls.get("expiry_days", "-")
        table.add_row(meta.get("target","-"), protocols, issuer, str(expiry), str(len(r.get("findings",[]))))
    console.print(table)

# Nuclei printer
def _print_nuclei(results, tool_name="nuclei"):
    table = Table(title="NUCLEI Results")
    table.add_column("Target")
    table.add_column("Executed")
    table.add_column("Findings")
    table.add_column("Severity")
    for r in results:
        meta = r.get("metadata", {})
        exec_count = meta.get("templates_executed", "-")
        findings = r.get("findings", [])
        sevcount = {}
        for f in findings:
            sevcount[f.get("severity","info")] = sevcount.get(f.get("severity","info"),0)+1
        sev_summary = ", ".join(f"{k}:{v}" for k,v in sevcount.items()) or "-"
        table.add_row(meta.get("target","-"), str(exec_count), str(len(findings)), sev_summary)
    console.print(table)

# Dispatcher used by CLI
def print_tool_summary(results, tool_name: str):
    if tool_name == "nmap":
        _print_nmap(results, tool_name)
    elif tool_name == "httpx":
        _print_httpx(results, tool_name)
    elif tool_name == "tlsinfo":
        _print_tlsinfo(results, tool_name)
    elif tool_name == "nuclei":
        _print_nuclei(results, tool_name)
    else:
        _print_generic(results, tool_name)



# -----------------------------------------------------------
# Commands
# -----------------------------------------------------------

@app.command("list-modules")
def list_modules():
    runner = Runner()
    modules = runner.registry.list_modules()

    table = Table(title="Available Modules")
    table.add_column("Module")
    table.add_column("Description")

    for name in modules:
        cls = runner.registry.get(name)
        inst = cls(config=None, logger=None)  # SAFE
        table.add_row(name, inst.description)

    console.print(table)


@app.command("list-runs")
def list_runs():
    if not os.path.exists(RESULTS_DIR):
        console.print("[yellow]No runs yet.[/yellow]")
        raise typer.Exit()

    runs = sorted(os.listdir(RESULTS_DIR))
    if not runs:
        console.print("[yellow]No runs found.[/yellow]")
        raise typer.Exit()

    table = Table(title="Scan History")
    table.add_column("Run ID", style="green")
    table.add_column("Targets")
    table.add_column("Tools")
    table.add_column("Timestamp")

    for run in runs:
        meta_path = os.path.join(RESULTS_DIR, run, "meta.json")
        if not os.path.exists(meta_path):
            continue
        with open(meta_path, "r") as f:
            meta = json.load(f)

        table.add_row(
            run,
            ", ".join(meta.get("targets", [])),
            ", ".join(meta.get("tools", [])),
            meta.get("timestamp", "")
        )

    console.print(table)


@app.command("scan")
def scan(
    tool: Optional[str] = typer.Option(None, "--tool", "-t"),
    all_tools: bool = typer.Option(False, "--all"),
    target: Optional[str] = typer.Option(None, "--target"),
    scan_type: str = typer.Option(
        None,
        "--type",
        "-p",
        help="Nmap scan type: short, fast, deep, discovery, firewall-bypass, slow"
    ),
    targets_file: Optional[str] = typer.Option(None, "--targets-file", "-f"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency"),
):
    cfg_loader = ConfigLoader().load()
    runner = Runner()
    runner.selected_scan_type = scan_type

    if concurrency:
        runner.global_cfg.concurrency = concurrency

    # ----------------------- COLLECT TARGETS ----------------------
    targets = []

    if target:
        targets.append(target.strip())

    if targets_file:
        with open(targets_file, "r") as f:
            targets.extend([ln.strip() for ln in f if ln.strip()])

    if not targets:
        console.print("[yellow]No targets provided.[/yellow]")
        user_in = Prompt.ask("Enter a target or comma-separated list")
        targets = [t.strip() for t in user_in.split(",")]

    run_id = _format_run_id(targets)

    # ----------------------- EXECUTE -------------------------
    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), TimeElapsedColumn()) as progress:
        task = progress.add_task("Scanning...", total=1)

        if all_tools:
            results = runner.execute_all(targets)
        else:
            if not tool:
                console.print("[red]Specify --tool or use --all[/red]")
                raise typer.Exit(1)
            results = {tool: runner.execute_tool_multi(tool, targets)}

        progress.update(task, advance=1)

    # Print result table
    for tname, tresults in results.items():
        print_tool_summary(tresults, tname)

    # Save results
    folder = _save_results_into_run_folder(run_id, results, targets)
    console.print(f"\n[green]Run saved to:[/green] {folder}")


@app.command("report")
def report(run: str = typer.Option(..., "--run", help="Run ID to generate report for")):
    run_folder = os.path.join(RESULTS_DIR, run)
    if not os.path.exists(run_folder):
        console.print(f"[red]Run folder not found: {run}[/red]")
        raise typer.Exit()

    # Load tool JSON
    results = {}
    for file in os.listdir(run_folder):
        if file.endswith(".json") and file != "meta.json":
            tool_name = file.replace(".json", "")
            with open(os.path.join(run_folder, file)) as f:
                results[tool_name] = json.load(f)

    # Load meta
    with open(os.path.join(run_folder, "meta.json")) as f:
        meta = json.load(f)

    # Correct template path
    template_path = os.path.join(
        os.path.dirname(__file__),
        "report",
        "templates",
        "report.html"
    )

    engine = ReportEngine(template_path=template_path)

    for tool, data in results.items():
        engine.add_run_result(tool, data)

    output_path = os.path.join(run_folder, "report.html")
    engine.generate_html(
        run,
        output_filename=output_path,
        target=",".join(meta.get("targets", []))
    )

    console.print(f"[green]Report generated successfully:[/green] {output_path}")


def main():
    app()


if __name__ == "__main__":
    main()

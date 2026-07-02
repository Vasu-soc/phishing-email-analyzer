import argparse
import sys
import os
from typing import Optional, List, Tuple
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Adjust python path if run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishing_analyzer.config import load_config
from phishing_analyzer.scoring import ScoringEngine, AnalysisResult
from phishing_analyzer.utils import (
    setup_logger,
    get_logger,
    read_email_file,
    parse_email_text,
    export_json_report,
    export_pdf_report
)

# Custom color theme for Phishing Analyzer
custom_theme = Theme({
    "safe": "bold green",
    "low": "green",
    "medium": "bold yellow",
    "high": "bold red",
    "very_high": "bold white on red",
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "highlight": "bold magenta"
})

console = Console(theme=custom_theme)

# Dictionary of built-in sample emails
SAMPLES = {
    "1": ("phishing_1.txt", "PayPal Account Suspension (Phishing)"),
    "2": ("phishing_2.txt", "IRS Refund Claim (Phishing)"),
    "3": ("phishing_3.txt", "Microsoft Password Alert (Phishing)"),
    "4": ("legitimate_1.txt", "Weekly Team Synchronization (Legitimate)"),
    "5": ("legitimate_2.txt", "GitHub Security Advisory (Legitimate)")
}

def get_sample_path(filename: str) -> str:
    """Returns absolute path to a sample file."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # The file resides in samples/phishing or samples/legitimate
    subfolder = "phishing" if "phishing" in filename else "legitimate"
    return os.path.join(current_dir, "samples", subfolder, filename)


def select_sample_interactive() -> Tuple[str, str]:
    """Prompts the user to select one of the built-in sample emails."""
    console.print("\n[info]Available Sample Emails:[/info]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("No.", style="dim", width=4)
    table.add_column("Sample Name")
    table.add_column("Type", width=12)

    for k, (_, name) in SAMPLES.items():
        email_type = "Phishing" if "Phishing" in name else "Legitimate"
        style = "high" if email_type == "Phishing" else "safe"
        table.add_row(k, name, Text(email_type, style=style))

    console.print(table)
    
    while True:
        try:
            choice = input("Select a sample number (1-5) or 'q' to quit: ").strip()
            if choice.lower() == 'q':
                sys.exit(0)
            if choice in SAMPLES:
                filename, name = SAMPLES[choice]
                return get_sample_path(filename), name
            console.print("[warning]Invalid selection. Please choose a number from 1 to 5.[/warning]")
        except KeyboardInterrupt:
            console.print("\n[warning]Operation cancelled.[/warning]")
            sys.exit(0)


def display_banner() -> None:
    """Prints a styled banner for the Phishing Email Analyzer CLI."""
    banner_text = Text()
    banner_text.append("=== Phishing Email Analyzer ===\n", style="bold cyan")
    banner_text.append("Rule-Based Heuristics & Risk Scoring Engine\n", style="dim")
    banner_text.append("Production-Quality SOC Analyst Portfolio Tool", style="italic yellow")
    
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def display_results(result: AnalysisResult) -> None:
    """Displays the analysis result in a clean, colorized terminal UI."""
    console.print("\n[info]=== Analysis Details ===[/info]")
    
    # 1. Metadata Table
    meta_table = Table(show_header=False, box=None)
    meta_table.add_column("Key", style="bold dim", width=18)
    meta_table.add_column("Value")
    
    meta_table.add_row("Subject:", result.subject if result.subject else "(No Subject)")
    meta_table.add_row("Timestamp:", result.timestamp)
    meta_table.add_row("Indicators Found:", str(len(result.matches)))
    console.print(meta_table)
    console.print("-" * 50)

    # 2. Risk Level Card
    risk_style = result.risk_level.lower().replace(" ", "_")
    score_bar = "#" * (result.final_score // 5) + "-" * (20 - (result.final_score // 5))
    
    risk_card = Text()
    risk_card.append(f"RISK LEVEL: {result.risk_level.upper()}\n", style=risk_style)
    risk_card.append(f"Phishing Score: {result.final_score}/100\n", style="bold")
    risk_card.append(f"Score Gauge:  [{score_bar}]", style="dim")
    
    console.print(Panel(risk_card, title="Assessment Summary", border_style=risk_style, expand=False))

    # 3. Detailed Findings List
    console.print("\n[info]=== Detailed Findings ===[/info]")
    if not result.matches:
        console.print("[safe][+] No phishing indicators were detected in this email.[/safe]")
    else:
        for idx, match in enumerate(result.matches, 1):
            category_display = match.category.replace("_", " ").title()
            
            finding_text = Text()
            finding_text.append(f"{idx}. [{category_display}] ", style="bold magenta")
            finding_text.append(f"Found in {match.location.upper()}\n", style="italic cyan")
            finding_text.append(f"   Matched snippet: ", style="dim")
            finding_text.append(f"\"{match.matched_text}\"\n", style="bold yellow")
            finding_text.append(f"   Why suspicious:  ", style="dim")
            finding_text.append(f"{match.explanation}")
            
            console.print(finding_text)
            console.print()


def get_manual_input() -> Tuple[str, str]:
    """Prompts user to enter email subject and body manually."""
    console.print("\n[info]=== Manual Email Input ===[/info]")
    try:
        subject = input("Enter Email Subject (optional, press Enter to skip): ").strip()
        console.print("Enter Email Body (Press Ctrl-D (Unix) or Ctrl-Z + Enter (Windows) when done):")
        body_lines = []
        while True:
            try:
                line = input()
                body_lines.append(line)
            except EOFError:
                break
        body = "\n".join(body_lines).strip()
        return subject, body
    except KeyboardInterrupt:
        console.print("\n[warning]Operation cancelled.[/warning]")
        sys.exit(0)


def main() -> None:
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="Analyze email text files or manual input for phishing indicators."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "email_file",
        nargs="?",
        help="Path to the email text file to analyze."
    )
    group.add_argument(
        "-m", "--manual",
        action="store_true",
        help="Input email content manually via terminal."
    )
    group.add_argument(
        "-s", "--sample",
        nargs="?",
        const="prompt",
        choices=["1", "2", "3", "4", "5", "prompt"],
        help="Run analysis on one of the built-in sample emails. If no number is provided, lists samples."
    )
    
    parser.add_argument(
        "-c", "--config",
        help="Path to a custom configuration YAML file."
    )
    parser.add_argument(
        "-j", "--json",
        help="Path to save the analysis report as JSON."
    )
    parser.add_argument(
        "-p", "--pdf",
        help="Path to save the analysis report as PDF."
    )
    parser.add_argument(
        "-l", "--log",
        default="logs/analysis.log",
        help="Path to the log file (default: logs/analysis.log)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging."
    )

    args = parser.parse_args()

    # 1. Setup Logger
    logger = setup_logger(log_file=args.log, verbose=args.verbose)
    logger.debug("Phishing Email Analyzer initiated.")

    # 2. Load Configuration
    config_file = args.config
    try:
        config = load_config(config_file)
        logger.debug(f"Configuration loaded (custom config: {bool(config_file)}).")
    except Exception as e:
        console.print(f"[error]Failed to load configuration: {e}[/error]")
        logger.error(f"Failed to load configuration: {e}", exc_info=True)
        sys.exit(1)

    # 3. Gather Subject & Body
    subject = ""
    body = ""
    source_name = "Manual Input"

    if args.manual:
        subject, body = get_manual_input()
        logger.info("Gathered email content from manual terminal input.")
    elif args.sample:
        if args.sample == "prompt":
            sample_path, sample_name = select_sample_interactive()
        else:
            filename, sample_name = SAMPLES[args.sample]
            sample_path = get_sample_path(filename)
        
        source_name = f"Sample: {sample_name}"
        try:
            subject, body = read_email_file(sample_path)
            logger.info(f"Loaded built-in sample email: {sample_name}")
        except Exception as e:
            console.print(f"[error]Failed to load sample email '{sample_name}': {e}[/error]")
            logger.error(f"Failed to load sample email '{sample_name}': {e}")
            sys.exit(1)
    elif args.email_file:
        source_name = f"File: {args.email_file}"
        try:
            subject, body = read_email_file(args.email_file)
            logger.info(f"Loaded email from file: {args.email_file}")
        except Exception as e:
            console.print(f"[error]Failed to read email file: {e}[/error]")
            logger.error(f"Failed to read email file: {e}")
            sys.exit(1)
    else:
        # If no arguments are provided, default to listing and selecting samples
        sample_path, sample_name = select_sample_interactive()
        source_name = f"Sample: {sample_name}"
        try:
            subject, body = read_email_file(sample_path)
            logger.info(f"No source arguments. Selected built-in sample email: {sample_name}")
        except Exception as e:
            console.print(f"[error]Failed to load sample email '{sample_name}': {e}[/error]")
            logger.error(f"Failed to load sample email '{sample_name}': {e}")
            sys.exit(1)

    if not body:
        console.print("[warning]Warning: Email body is empty. Analysis might not yield complete results.[/warning]")
        logger.warning("Empty email body submitted for analysis.")

    # 4. Perform Analysis
    try:
        engine = ScoringEngine(config)
        logger.debug("Scoring engine initialized, beginning email analysis.")
        
        result = engine.analyze(subject, body)
        logger.info(f"Analysis completed. Score: {result.final_score}/100, Risk Level: {result.risk_level}")
    except Exception as e:
        console.print(f"[error]An error occurred during analysis: {e}[/error]")
        logger.error(f"An error occurred during analysis: {e}", exc_info=True)
        sys.exit(1)

    # 5. Display Results in CLI
    display_results(result)

    # 6. Report Exporting
    # Export JSON Report
    if args.json:
        try:
            export_json_report(result, args.json)
            console.print(f"[safe][+] JSON report exported to: {args.json}[/safe]")
            logger.info(f"Exported JSON report to: {args.json}")
        except Exception as e:
            console.print(f"[error]Failed to export JSON report: {e}[/error]")
            logger.error(f"Failed to export JSON report: {e}")

    # Export PDF Report
    if args.pdf:
        try:
            export_pdf_report(result, args.pdf)
            console.print(f"[safe][+] PDF report exported to: {args.pdf}[/safe]")
            logger.info(f"Exported PDF report to: {args.pdf}")
        except Exception as e:
            console.print(f"[error]Failed to export PDF report: {e}[/error]")
            logger.error(f"Failed to export PDF report: {e}")


if __name__ == "__main__":
    main()

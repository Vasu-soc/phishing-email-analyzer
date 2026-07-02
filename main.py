#!/usr/bin/env python
"""
Phishing Email Analyzer
Main entry point. Use --web to launch the browser-based UI.
"""
import sys
import os

# Ensure the project root is on the import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if "--web" in sys.argv or len(sys.argv) == 1:
        # Check if --web was explicitly requested OR no args given → prefer Web UI
        if "--web" in sys.argv or _prefer_web():
            from phishing_analyzer.server import run_server
            debug = "--debug" in sys.argv
            run_server(host="127.0.0.1", port=7777, debug=debug)
            return

    # Fallback: run CLI mode
    from phishing_analyzer.main import main as cli_main
    cli_main()


def _prefer_web() -> bool:
    """Return True if running without arguments (interactive Web UI is friendlier)."""
    # When no positional args or option flags are present, prefer the web UI.
    meaningful = [a for a in sys.argv[1:] if not a.startswith("#")]
    return len(meaningful) == 0


if __name__ == "__main__":
    main()

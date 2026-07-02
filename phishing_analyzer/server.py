"""
Flask Web Server for Phishing Email Analyzer.

Provides REST API endpoints that power the split-panel browser UI:
  GET  /          – Serve the main index page
  POST /analyze   – Accept raw text or uploaded file, run analysis, return JSON
  GET  /logs      – Return the last 50 lines of the analysis log
  GET  /download/<fmt> – Download JSON or PDF report from latest analysis
"""

import os
import io
import json
import logging
import tempfile
from datetime import datetime, timezone
from typing import Optional

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    abort,
)

# ---------------------------------------------------------------------------
# Bootstrap: ensure project root is on the import path when running directly
# ---------------------------------------------------------------------------
import sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from phishing_analyzer.config import load_config
from phishing_analyzer.scoring import ScoringEngine
from phishing_analyzer.utils.logger import setup_logger
from phishing_analyzer.utils.io import parse_email_text
from phishing_analyzer.utils.report import export_json_report, export_pdf_report

# ---------------------------------------------------------------------------
# Logging helper at module scope
# ---------------------------------------------------------------------------
logger = logging.getLogger("phishing_analyzer.server")

def _extract_text_from_upload(file_storage) -> str:
    """Return plain text from an uploaded TXT or PDF file.

    For PDF files the following extraction chain is tried in order:
      1. pypdf        – works for PDFs that have a real text layer.
      2. PyMuPDF      – better Unicode/layout recovery for some PDFs.
      3. pytesseract  – OCR for scanned / image-only PDFs (requires
                        the Tesseract binary to be installed).

    If no strategy yields usable text the sentinel string
    ``'__IMAGE_ONLY_PDF__'`` is returned so the caller can send
    the user a descriptive error message.
    """
    filename = file_storage.filename or ""
    ext      = os.path.splitext(filename)[-1].lower()
    raw      = file_storage.read()

    if ext != ".pdf":
        return raw.decode("utf-8", errors="ignore")

    # ── Strategy 1: pypdf (works for text-layer PDFs) ─────────────────
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        text   = "\n".join([p.extract_text() or "" for p in reader.pages]).strip()
        if text:
            logger.info("PDF text extracted via pypdf (%d chars).", len(text))
            return text
    except Exception as exc:
        logger.debug("pypdf failed: %s", exc)

    # ── Strategy 2: PyMuPDF – better for some encodings ───────────────
    try:
        import fitz  # PyMuPDF
        doc  = fitz.open(stream=raw, filetype="pdf")
        text = "\n".join([page.get_text("text") for page in doc]).strip()
        if text:
            logger.info("PDF text extracted via PyMuPDF (%d chars).", len(text))
            return text
    except ImportError:
        logger.debug("PyMuPDF not installed; skipping strategy 2.")
    except Exception as exc:
        logger.debug("PyMuPDF failed: %s", exc)

    # ── Strategy 3: OCR via pytesseract (image-only / scanned PDFs) ───
    try:
        import fitz
        import pytesseract
        from PIL import Image
        doc   = fitz.open(stream=raw, filetype="pdf")
        parts = []
        for page in doc:
            mat = fitz.Matrix(200 / 72, 200 / 72)  # 200 dpi
            pix = page.get_pixmap(matrix=mat)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            parts.append(pytesseract.image_to_string(img))
        text = "\n".join(parts).strip()
        if text:
            logger.info("PDF text extracted via OCR (%d chars).", len(text))
            return text
    except ImportError:
        logger.debug("pytesseract/PyMuPDF not available; OCR skipped.")
    except Exception as exc:
        logger.warning("OCR extraction failed: %s", exc)

    # ── All strategies failed – likely a rasterised image-only PDF ────
    logger.warning(
        "PDF '%s' yielded no extractable text. "
        "It appears to be an image-only document (e.g. Windows/Chrome Print-to-PDF).",
        filename,
    )
    return "__IMAGE_ONLY_PDF__"

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(config_path: Optional[str] = None) -> Flask:
    """Create and configure the Flask application."""

    template_dir = os.path.join(_HERE, "web", "templates")
    static_dir   = os.path.join(_HERE, "web", "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
    )
    from flask_cors import CORS
    CORS(app)
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit

    # ------------------------------------------------------------------
    # Internal state – store the most-recent analysis result so the
    # /download routes can regenerate reports without re-analysis.
    # ------------------------------------------------------------------
    _state: dict = {"last_result": None}

    # ------------------------------------------------------------------
    # Logging & engine
    # ------------------------------------------------------------------
    # Vercel serverless runs on a read-only filesystem – only /tmp is writable.
    _on_vercel = bool(os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"))
    if _on_vercel:
        log_path = "/tmp/analysis.log"
    else:
        log_path = os.path.join(_ROOT, "logs", "analysis.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # Configures logging handler (file + console)
    setup_logger(log_file=log_path, verbose=False)

    cfg    = load_config(config_path)
    engine = ScoringEngine(cfg)


    # ==================================================================
    # Routes
    # ==================================================================

    @app.route("/")
    def index():
        return render_template("index.html")


    @app.route("/analyze", methods=["POST"])
    def analyze():
        """
        Accept either:
          • multipart/form-data with a file field named 'email_file', OR
          • application/json  with fields {"subject": "…", "body": "…"}
          • form field 'email_text' for pasted raw content
        """
        subject = ""
        body    = ""

        # -- File upload --------------------------------------------------
        if "email_file" in request.files:
            uploaded = request.files["email_file"]
            if uploaded.filename:
                raw_text = _extract_text_from_upload(uploaded)
                if raw_text == "__IMAGE_ONLY_PDF__":
                    return jsonify({
                        "error": (
                            "This PDF contains no extractable text — it was saved as an image "
                            "(e.g. using Windows Print to PDF or Chrome Print). "
                            "Please open your email, copy all the text, then use the "
                            "\"Paste Content\" tab to analyse it."
                        ),
                        "hint": "switch_to_paste",
                    }), 422
                subject, body = parse_email_text(raw_text)
            else:
                return jsonify({"error": "Empty file received."}), 400

        # -- Pasted text --------------------------------------------------
        elif "email_text" in request.form:
            raw_text        = request.form["email_text"]
            subject, body   = parse_email_text(raw_text)

        # -- JSON body ----------------------------------------------------
        elif request.is_json:
            data    = request.get_json(silent=True) or {}
            subject = data.get("subject", "")
            body    = data.get("body", "")

        else:
            return jsonify({"error": "No email content provided."}), 400

        if not body.strip():
            return jsonify({"error": "Email body is empty – nothing to analyze."}), 400

        # -- Run detection ------------------------------------------------
        logger.info("Web UI analysis started (subject length=%d, body length=%d)",
                    len(subject), len(body))
        result = engine.analyze(subject, body)
        _state["last_result"] = result
        _state["last_subject"] = subject
        _state["last_body"]    = body
        logger.info(
            "Web UI analysis complete. Score: %d/100, Risk Level: %s",
            result.final_score, result.risk_level,
        )

        # -- Build response payload ---------------------------------------
        payload = result.to_dict()

        # Add indicator groupings for richer frontend rendering
        payload["indicators"] = [
            {
                "category":     m.category.replace("_", " ").title(),
                "raw_category": m.category,
                "matched_text": m.matched_text,
                "pattern":      m.pattern,
                "explanation":  m.explanation,
                "location":     m.location.upper(),
            }
            for m in result.matches
        ]

        # Persist to /tmp so download works across serverless invocations
        try:
            with open("/tmp/last_result.json", "w", encoding="utf-8") as fh:
                json.dump({"subject": subject, "body": body, "payload": payload}, fh)
        except Exception:
            pass  # Non-fatal; in-memory _state will be used if available

        return jsonify(payload)


    @app.route("/logs")
    def get_logs():
        """Return the last 60 lines of the analysis log as JSON."""
        try:
            if not os.path.exists(log_path):
                return jsonify({"lines": []})
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
            return jsonify({"lines": [l.rstrip() for l in lines[-60:]]})
        except Exception as exc:
            return jsonify({"lines": [f"[ERROR] Could not read log: {exc}"]}), 500


    @app.route("/download/<fmt>")
    def download_report(fmt: str):
        """Generate and download a report for the most recent analysis.

        On Vercel, each request may hit a fresh serverless instance so
        _state is empty.  We fall back to /tmp/last_result.json which was
        written by the /analyze handler in the same or a prior invocation.
        """
        result = _state.get("last_result")

        # Serverless fall-back: re-run analysis from persisted input
        if result is None:
            try:
                with open("/tmp/last_result.json", "r", encoding="utf-8") as fh:
                    saved = json.load(fh)
                result = engine.analyze(
                    saved.get("subject", ""), saved.get("body", "")
                )
            except Exception:
                abort(404, description="No analysis has been run yet.")

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if fmt == "json":
            tmp = tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, dir=tempfile.gettempdir()
            )
            tmp.close()
            export_json_report(result, tmp.name)
            return send_file(
                tmp.name,
                as_attachment=True,
                download_name=f"phishing_report_{ts}.json",
                mimetype="application/json",
            )

        elif fmt == "pdf":
            tmp = tempfile.NamedTemporaryFile(
                suffix=".pdf", delete=False, dir=tempfile.gettempdir()
            )
            tmp.close()
            export_pdf_report(result, tmp.name)
            return send_file(
                tmp.name,
                as_attachment=True,
                download_name=f"phishing_report_{ts}.pdf",
                mimetype="application/pdf",
            )

        else:
            abort(400, description=f"Unknown format '{fmt}'. Use 'json' or 'pdf'.")

    return app


# ---------------------------------------------------------------------------
# Standalone runner (used by main.py --web)
# ---------------------------------------------------------------------------

def run_server(host: str = "127.0.0.1", port: int = 7777, debug: bool = False):
    app = create_app()
    print(f"\n  Phishing Email Analyzer - Web UI")
    print(f"  Running at  http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=debug)

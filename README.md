# Phishing Email Analyzer

A modular, rule-based heuristics & risk scoring engine built in Python to analyze email subjects and bodies for phishing indicators. This tool is designed to assist SOC (Security Operations Center) analysts in triaging suspicious emails by assigning a numeric risk score and providing detailed explanations for each flagged indicator.

## Key Features

- **Multi-Strategy PDF Parsing**: Seamlessly extracts email content from uploaded PDF files using a tiered fallback extraction pipeline:
  - **pypdf**: Extracts text directly from standard text-layer documents.
  - **PyMuPDF**: Resolves complex font encodings and layout formats.
  - **OCR/pytesseract Support**: Identifies image-only or scanned PDFs (such as browser/Gmail Print-to-PDF printouts) and alerts the user to switch to manual text pasting to prevent blank analysis reports.
- **Urgency & Threat Detection**: Scans for coercive and threatening language using configurable wordlists.
- **Suspicious URL Analysis**: Evaluates links using regular expressions to detect:
  - Unencrypted connections (HTTP links)
  - URL shorteners (e.g., `bit.ly`, `tinyurl.com`)
  - IP-address-based hosts (e.g., `http://192.168.x.x`)
  - Cheap/suspicious TLDs commonly used in phishing (`.xyz`, `.top`, `.tk`, etc.)
  - Lookalike subdomain spoofing (e.g., `paypal.com.malicious-domain.xyz`)
- **Generic Greetings Identification**: Detects generic recipient addresses such as "Dear Customer" or "Dear User" which are hallmarks of broad-scale phishing campaigns.
- **Sensitive Request Detection**: Identifies requests for credentials, OTPs, PINs, social security numbers, and financial/billing details.
- **Social Engineering Flags**: Catches persuasion tactics and call-to-actions like "Click here" or "Claim your reward".
- **Weighted Scoring Engine**: Calculates a normalized phishing risk score from 0 to 100 and maps it to a risk level (`Safe`, `Low`, `Medium`, `High`, `Very High`).
- **Comprehensive Reports**: Automatically generates detailed analysis reports in both **JSON** and **PDF** formats.
- **Log Management**: Records analysis activities and outcomes in a centralized log file.

---

## Project Directory Architecture

```text
├── .gitignore                 # Files and folders to ignore in Git
├── main.py                    # Root entry point wrapper
├── phishing_analyzer/         # Core application package
│   ├── config/
│   │   ├── __init__.py
│   │   ├── default_config.yaml# Configurable keyword lists, weights, and thresholds
│   │   └── loader.py          # Configuration loading & merging logic
│   ├── detectors/
│   │   ├── __init__.py        # Base detector class and match dataclass definitions
│   │   ├── urgency.py         # Urgency/threat heuristics
│   │   ├── url.py             # Suspicious URL regex analyzer
│   │   ├── greeting.py        # Generic greeting identifier
│   │   ├── credential.py      # Sensitive credentials request detector
│   │   └── social_engineering.py # Persuasive phrase detector
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── engine.py          # Aggregates matches and computes normalized score
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── io.py              # Subject-body parser and file loading utility
│   │   ├── report.py          # Exporter for JSON and ReportLab PDF documents
│   │   └── logger.py          # Standard logging handler setup
│   ├── samples/
│   │   ├── phishing/          # Sample phishing .txt templates for testing
│   │   └── legitimate/        # Sample legitimate .txt templates for testing
│   ├── tests/                 # Unit tests directory
│   │   ├── test_urgency.py
│   │   ├── test_url.py
│   │   ├── test_greeting.py
│   │   ├── test_credential.py
│   │   ├── test_social_engineering.py
│   │   ├── test_pdf_parser.py # Unit tests for PDF parsing strategies
│   │   └── test_engine.py
│   └── main.py                # Main CLI script implementation
├── requirements.txt           # Python package requirements
├── setup.py                   # Setup script for installation
└── README.md                  # Project documentation (this file)
```

---

## Installation & Setup

1. **Clone or copy this repository** into your local directory.
2. Ensure you have **Python 3.8+** installed.
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. (Optional) Install the package in editable mode:
   ```bash
   pip install -e .
   ```

---

## Usage Guide

The analyzer provides a simple command-line interface with several runtime options:

```bash
python main.py [options] [email_file]
```

### Command-line Arguments & Options

| Command / Option | Description |
| :--- | :--- |
| `email_file` | Path to a text file containing the email to analyze (positional). |
| `-m`, `--manual` | Prompts for manual multi-line text input directly in the console. |
| `-s`, `--sample` | Runs a built-in sample email. Prompts an interactive selection menu if run without arguments. |
| `-c`, `--config` | Path to a custom YAML configuration file. |
| `-j`, `--json` | Path to save the output report in JSON format. |
| `-p`, `--pdf` | Path to save the output report in PDF format. |
| `-l`, `--log` | Location to write application logs (default: `logs/analysis.log`). |
| `-v`, `--verbose`| Activates detailed debug console output. |

### Execution Examples

#### 1. Running built-in sample emails (Interactive Menu)
```bash
python main.py
```

#### 2. Running a specific sample and generating PDF & JSON reports
```bash
python main.py --sample 1 --json reports/report.json --pdf reports/report.pdf
```

#### 3. Analyzing a custom local email file
```bash
python main.py path/to/email.txt --pdf reports/analysis.pdf
```

#### 4. Manual input mode
```bash
python main.py --manual --pdf reports/manual_analysis.pdf
```

#### 5. Running the Web UI Server
```bash
python main.py --web
```

---

## Chrome Extension for Gmail Integration

This project includes a **Chrome Extension** (Manifest V3) located in the `chrome_extension/` directory that extracts email subjects and bodies directly from Gmail to scan them.

### How to Install:
1. Start your local analyzer server:
   ```bash
   python main.py --web
   ```
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer Mode** (top-right toggle switch).
4. Click **"Load unpacked"** and select the `chrome_extension/` folder from this project.
5. The shield icon will appear in your extensions list.

### How to Use:
1. Open any email thread in **Gmail** (`https://mail.google.com`).
2. A blue **"Scan Email"** button will automatically inject itself next to the email's subject line.
3. Click **Scan Email** to query your local server.
4. An elegant overlay dashboard will display the risk score, badge level, and details for all flagged indicators directly in your tab.

---

## Heuristic Weighting & Scoring Details

The tool computes a normalized score (0–100) based on categories loaded from `phishing_analyzer/config/default_config.yaml`:

- **Urgency keywords**: Base weight 15
- **Suspicious URLs**: Base weight 25
- **Generic greetings**: Base weight 10
- **Sensitive requests**: Base weight 25
- **Social Engineering**: Base weight 25

### Scoring Heuristics
- The **first** detection in a category adds 100% of the category weight to the score.
- **Subsequent detections** in the same category add a minor increment (+3 points per extra match), up to a ceiling of 1.5x the base category weight.
- A **subject-line match** adds a flat **+5 points** bonus (lure detection).
- Risk thresholds are defined as:
  - `0`: **Safe**
  - `1 - 34`: **Low**
  - `35 - 59`: **Medium**
  - `60 - 79`: **High**
  - `80 - 100`: **Very High**

---

## Limitations

- **Rule-based Detection**: Heuristics are based on static keyword and regex patterns. Attackers can bypass detection by obfuscating keywords, using images, or crafting non-standard phrasings.
- **Lack of Authentication Checks**: This tool does not perform live domain checks, SPF/DKIM/DMARC alignment validation, or reputation inquiries.
- **False Positives**: Standard automated notifications (e.g. system alerts, invoice receipts) containing terms like "urgent update" or "click here" can trigger high phishing scores.

---

## Vercel Deployment

This repository is pre-configured for one-click deployment on [Vercel](https://vercel.com) using Vercel Serverless Functions:

1. **Configurations Added**:
   - `api/index.py`: Serverless handler exporting the Flask application.
   - `vercel.json`: Defines routes and compiles python assets using `@vercel/python`.
2. **How to Deploy**:
   - Install the Vercel CLI: `npm install -g vercel`
   - Run the deployment command inside the project directory:
     ```bash
     vercel
     ```
   - Follow the prompts to log in and link the project. Vercel will build and deploy the app automatically!
   - Alternatively, connect your GitHub repository directly to Vercel and it will auto-deploy on every push.

---

## Future Enhancements

1. **Header Validation**: Extract and verify SPF, DKIM, and DMARC headers from raw `.eml` files.
2. **External Threat Intel Integration**: Query active reputations of extracted links using APIs like VirusTotal or Google Safe Browsing.
3. **Machine Learning Model**: Train a classifier (e.g., TF-IDF + Naive Bayes or BERT embeddings) to work in tandem with rule-based heuristics to identify novel phishing emails.
4. **Attachment Analysis**: Inspect attached files (hashes, extensions) for known malware indices or malicious macros.

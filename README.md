# AI Security Pipeline Guard

A Python-based CLI scanner and GitHub Action designed to detect security flaws in source code and Docker configurations using the Gemini API. 

The project implements a hybrid approach: it combines traditional deterministic security filters (Regex) with LLM analysis to enforce security rules without leaking sensitive data to the cloud.



##  How It Works (Pipeline Steps)

1. **Policy-as-Code:** The scanner loads security guidelines from a decoupled configuration file (`rules/docker_rules.json`).
2. **Local DLP Pre-filter:** Before making any cloud API calls, a local pre-compiled regex filter inspects the code. If any hardcoded credentials (API keys, AWS tokens, passwords) are found, they are redacted locally (`re.subn()`).
3. **Resilient API Request:** The sanitized code and the JSON policy are sent to the Gemini API. The network call is wrapped in a `Tenacity` retry decorator using exponential backoff to handle rate limits or transient errors.
4. **Schema Enforcement:** The raw JSON output from the AI is validated against a strict structure using a `Pydantic` model (`BaseModel`). Any malformed response or hallucination triggers a handled `ValidationError`.
5. **Deterministic Override (Safety Fuse):** If the local DLP filter detected a secret in Step 2, the Python script automatically overrides the AI's verdict, forcing the final status to `NON_COMPLIANT` and injecting a local priority alert.
6. **Artifact Output:** The validated result is saved as a structured JSON report in the `reports/` directory with a unique timestamp.



##  Project Structure

```text
├── rules/          # Security rules in JSON format (Policy-as-Code)
├── src/            # Core Python scanner logic (scanner.py)
├── tests/          # Automated unit tests (test_scanner.py)
├── reports/        # Generated JSON audit reports (Git-ignored)
├── examples/       # Vulnerable code samples used for scanner testing
├── .github/        # CI/CD pipelines (GitHub Actions Workflow)
└── requirements.txt# Project dependencies with minimal version constraints


```
##  Setup & Installation

Prerequisites
Python 3.10+

A Google Gemini API Key

1. Install Dependencies
Install all required production and testing libraries from the package manifest:

Bash
pip install -r requirements.txt

2. Configure Credentials
Create a .env file in the root directory of the project and add your API key:

Bash
GOOGLE_API_KEY=your_actual_gemini_api_key_here
(Note: The .env file is automatically ignored by Git to prevent accidental leaks).

## Usage
Full Scan (Default)
Scans all compatible code and configuration files found in the target directories:
Bash
python src/scanner.py


Incremental Scan (CI/CD Optimized)
Pass specific file paths via command-line arguments to scan only modified files, saving memory and API quota:
Bash
python src/scanner.py examples/insecure_app.py


##  Running Tests
The project includes an automated test suite powered by pytest to verify the regular expressions and the local override logic. To execute the tests, run:

Bash
pytest


## CI/CD Automation
This scanner is designed to run automatically on every code change. The repository includes a GitHub Actions workflow located in .github/workflows/security_scan.yml. It triggers an audit on every push and pull_request, pulling the API credentials securely from GitHub encrypted secrets.
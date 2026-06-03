## AI Security Pipeline Guard

A DevSecOps tool automating security audits for both **application source code** and **infrastructure (IaC)**. It leverages dynamic prompts and LLM models (Google Gemini) to detect security vulnerabilities based on defined policies (Policy-as-Code).




## Key Features

* **Data Leak Prevention (DLP):** Locally masks hardcoded secrets (API keys, AWS tokens, passwords) using regex *before* any data is sent to the LLM.
* **Incremental Scanning:** Accepts specific file paths via CLI arguments to scan only modified files, optimizing API usage and CI/CD execution time.
* **Context-Aware Scanning:** The system automatically identifies the file type and applies the appropriate analytical context:
    * `Infrastructure as Code` (Dockerfile/docker-compose): Scans for configuration vulnerabilities (e.g., root privileges, exposed ports, insecure base images).
    * `Application Code` (Python): Detects code-level vulnerabilities (e.g., SQL Injection, hardcoded secrets).
* **Policy-as-Code:** Security rules are maintained as flexible JSON files, decoupled from the core scanner logic.
* **API Resilience:** Built-in mechanisms for Rate Limiting and exponential backoff to handle HTTP 429/503 errors.
* **Automated Reporting:** Outputs results to structured `.json` files, ready for dashboard integration.




## Project Structure

```
├── rules/          # Policy definitions in JSON format (Policy-as-Code)
├── src/            # Core scanner logic and API integration (scanner.py)
├── tests/          # Unit tests for security filters (e.g., secret redaction)
├── reports/        # Automatically generated audit reports (.json)
├── examples/       # Testing ground: insecure .py and .Dockerfile examples
├── .github/        # CI/CD configuration (GitHub Actions Workflow)
└── .env            # Environment variables (ignored by Git)
```




## Installation and Setup

Requirements: Python 3.10+

Install dependencies:

Bash
pip install google-genai python-dotenv pytest

** API Key Configuration:
Create a .env file in the root directory and add your Google Gemini API key:

GOOGLE_API_KEY=your_api_key_here


Run the Scanner:

** Full Scan (Default): Scans all compatible files in the examples/ directory.

Bash
python src/scanner.py


** Incremental Scan (CI/CD Optimized): Provide specific file paths to scan only those files.

Bash
python src/scanner.py examples/insecure_app.py


** Testing

To ensure the local secret redaction filter is working correctly, run the automated test suite:

Bash
pytest




## CI/CD Integration (GitHub Actions)

This project is designed to run in a fully automated CI/CD environment. The provided example workflow triggers a security audit on every push to the repository (leveraging GitHub Secrets). The pipeline is configured in .github/workflows/security-scan.yml.



## Audit Standards

Depending on the file context, the system implicitly verifies compliance against industry standards utilizing the LLM's training knowledge:

OWASP Top 10 (Application vulnerabilities: Injection, Broken Access Control, hardcoded secrets).

CIS Benchmarks (Docker configuration, Least Privilege, resource management).



## License
Personal project (Internal/Private).
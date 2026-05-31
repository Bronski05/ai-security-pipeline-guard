<<<<<<< HEAD
AI Security Pipeline Guard

Narzędzie automatyzujące audyt bezpieczeństwa plików Dockerfile w oparciu o zdefiniowane polityki (Policy-as-Code) oraz analizę LLM.




Funkcjonalności

Policy-as-Code: Reguły bezpieczeństwa w formacie JSON, oddzielone od logiki skanera.

Analiza kontekstowa: Wykorzystanie modelu Gemini do wykrywania luk (m.in. hardkodowane sekrety, uprawnienia roota).

Raportowanie: Automatyczny zapis wyników do plików .json z podziałem na domeny bezpieczeństwa.

Resilience: Wbudowany mechanizm retry (exponential backoff) dla zapytań API.





Struktura projektu

├── rules/           # Definicje polityk (JSON)
├── src/             # Logika skanera (Python)
├── reports/         # Raporty z audytów (JSON)
├── examples/        # Testowe pliki Dockerfile
└── .env             # Zmienne środowiskowe (nie commitować!)




Instalacja i uruchomienie

Wymagania: Python 3.10+


Instalacja zależności:

Bash
pip install -r requirements.txt


Konfiguracja klucza API:

Stwórz plik .env i dodaj:

GOOGLE_API_KEY=twoj_klucz_api


Uruchomienie:

Bash
python src/scanner.py




Integracja (CI/CD)
Przykład wdrożenia w GitHub Actions:

YAML
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Scan
        run: python src/scanner.py
        env:
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}




Standardy audytu
System weryfikuje konfigurację pod kątem:

CIS Benchmarks (Docker)

NIST (Secrets & Supply Chain)

Least Privilege



Licencja
Projekt własny (Internal/Private).
=======
# ai-security-pipeline-guard
>>>>>>> 956190a21a35331d723ee9e109efcb5509713e86

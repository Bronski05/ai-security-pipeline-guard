import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from google import genai
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

class Violation(BaseModel):
    issue: str = Field(description="Opis wykrytej podatności")
    criticality: str = Field(description="Poziom zagrożenia: HIGH, MEDIUM, LOW")
    remediation: str = Field(description="Sposób naprawienia błędu")

class SecurityReport(BaseModel):
    status: str = Field(description="Status ogólny: COMPLIANT lub NON_COMPLIANT")
    violations: List[Violation] = Field(default=[])

def get_security_policy():
    """Wczytuje reguły bezpieczeństwa z pliku JSON (Policy-as-Code)."""
    try:
        with open('rules/docker_rules.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"note": "Brak specyficznej polityki. Użyj ogólnych zasad bezpieczeństwa."}

def redact_secrets_locally(content):
    """Zabezpiecza hardcodowane sekrety przed wysłaniem do zewnętrznego API (DLP)."""
    pattern1 = re.compile(r'(?i)(api_key|password|secret|token)(\s*[:=]\s*)(["\'][a-zA-Z0-9_\-]+["\'])')
    sanitized, count1 = pattern1.subn(r'\1\2"[REDACTED_BY_SECURITY_SCANNER]"', content)
    
    pattern2 = re.compile(r'AKIA[A-Z0-9]{16}')
    sanitized, count2 = pattern2.subn(r'"[REDACTED_AWS_KEY]"', sanitized)
    
    has_secrets = (count1 + count2) > 0
    return sanitized, has_secrets

def get_system_prompt(file_path, policy):
    """Zwraca dedykowany prompt w zależności od analizowanego pliku."""
    filename = str(file_path).lower()
    if "docker" in filename or "compose" in filename:
        return f"""Jesteś ekspertem DevSecOps. Audytuj plik infrastruktury: {{content}}
        Polityka: {json.dumps(policy)}.
        Zwróć wynik WYŁĄCZNIE jako JSON zgodny ze schematem:
        {{"status": "NON_COMPLIANT", "violations": [{{"issue": "...", "criticality": "HIGH/MEDIUM/LOW", "remediation": "..."}}]}}
        Jeśli plik jest bezpieczny, zwróć {{"status": "COMPLIANT", "violations": []}}"""
    
    return """Jesteś ekspertem bezpieczeństwa kodu. Audytuj ten plik: {content}.
    Zwróć wynik WYŁĄCZNIE jako JSON zgodny ze schematem:
    {"status": "NON_COMPLIANT", "violations": [{"issue": "...", "criticality": "HIGH/MEDIUM/LOW", "remediation": "..."}]}
    Jeśli plik jest bezpieczny, zwróć {"status": "COMPLIANT", "violations": []}"""

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=4, max=15),
    reraise=True
)
def call_gemini_api_with_retry(prompt):
    """Wysyła zapytanie do API Gemini z automatycznym mechanizmem ponawiania prób."""
    return client.models.generate_content(
        model="gemini-1.5-flash", 
        contents=prompt,
    )

def run_security_scan(file_path, policy):
    """Główna funkcja skanująca plik przy pomocy lokalnych filtrów, Tenacity i Pydantic."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {
            "status": "ERROR",
            "violations": [{"issue": f"Nie można otworzyć pliku: {e}", "criticality": "HIGH", "remediation": "Sprawdź uprawnienia do pliku."}]
        }

    sanitized_content, has_secrets = redact_secrets_locally(content)
    if has_secrets:
        print(f"[INFO] Wykryto i zamaskowano sekrety w pliku {file_path}. Kontynuuję skanowanie ...")

    prompt = get_system_prompt(file_path, policy).replace("{content}", sanitized_content)
    
    try:
        response = call_gemini_api_with_retry(prompt)
        clean_json = response.text.replace('```json', '').replace('`', '').strip()
        
        report_data = SecurityReport.model_validate_json(clean_json)
        result_json = report_data.model_dump()
        
        if has_secrets:
            if result_json.get("status") == "COMPLIANT":
                result_json["status"] = "NON_COMPLIANT"
            
            local_violation = {
                "issue": "[LOCAL FILTER] Zamaskowano twardo zapisane hasło/klucz zapobiegając wyciekowi.",
                "criticality": "HIGH",
                "remediation": "Zmień poświadczenia i przenieś je do zmiennych środowiskowych."
            }
            result_json["violations"].insert(0, local_violation)
            
        return result_json

    except ValidationError as ve:
        return {
            "status": "ERROR", 
            "violations": [{"issue": f"Błąd walidacji danych (Pydantic): {ve}", "criticality": "HIGH", "remediation": "Zweryfikuj prompt lub model AI."}]
        }
    except Exception as e:
        return {
            "status": "ERROR", 
            "violations": [{"issue": f"Krytyczny błąd połączenia z API (Tenacity Fail): {e}", "criticality": "HIGH", "remediation": "Sprawdź status usługi chmurowej."}]
        }

def save_report(results):
    """Zapisuje gotowy raport do czytelnego pliku JSON."""
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/scan_{timestamp}.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n[INFO] Raport JSON zapisano w: {report_path}")

if __name__ == "__main__":
    policy = get_security_policy()
    targets = []
    
    if len(sys.argv) > 1:
        print("[INFO] Uruchomiono ze wskazanymi plikami. Skanuję tylko te podane w terminalu...")
        for arg in sys.argv[1:]:
            path = Path(arg)
            if path.exists() and path.is_file():
                targets.append(path)
            else:
                print(f"[WARN] Plik {arg} nie istnieje - pomijam.")
                
    else:
        print("[INFO] Brak argumentów. Skanuję domyślnie cały folder 'examples/'...")
        examples_path = Path('examples')
        if examples_path.exists():
            targets.extend(examples_path.rglob('*.py'))
            targets.extend(examples_path.rglob('*docker*'))
            
    if not targets:
        print("[INFO] Brak plików do przeskanowania. ")
        sys.exit(0)

    final_report = {"scan_date": str(datetime.now()), "files": {}}
    
    # Zmienna pomocnicza do śledzenia, czy znaleźliśmy błędy
    has_violations = False

    for target in targets:
        print(f"\n[SCANNING] {target}")
        result = run_security_scan(target, policy)
        final_report["files"][str(target)] = result
        
        #  Sprawdzamy na bieżąco, czy status to NON_COMPLIANT
        if result.get("status") == "NON_COMPLIANT":
            has_violations = True

    save_report(final_report)

    #  Jeśli wykryto błędy, kończymy z kodem 1, aby GitHub Actions zasygnalizował błąd
    if has_violations:
        print("\n[FAILURE] Skanowanie zakończone niepowodzeniem. Wykryto podatności bezpieczeństwa!")
        sys.exit(1)
    else:
        print("\n[SUCCESS] Wszystkie pliki są bezpieczne zgodne z polityką.")
        sys.exit(0)
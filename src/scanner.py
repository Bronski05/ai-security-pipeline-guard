import json
import os
import time
import re
from datetime import datetime
from pathlib import Path
from google import genai
from dotenv import load_dotenv

load_dotenv()
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

def get_security_policy():
    """Wczytuje reguły bezpieczeństwa z pliku JSON."""
    try:
        with open('rules/docker_rules.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"note": "Brak specyficznej polityki. Użyj ogólnych zasad bezpieczeństwa."}

def redact_secrets_locally(content):
    """
    Inteligentne maskowanie (Data Redaction).
    Wykrywa sekrety, podmienia je na bezpieczne wartości i zwraca oczyszczony kod.
    """
    # Szukamy zmiennych typu hasło/klucz i podmieniamy ich wartość
    pattern1 = re.compile(r'(?i)(api_key|password|secret|token)(\s*[:=]\s*)(["\'][a-zA-Z0-9_\-]+["\'])')
    sanitized, count1 = pattern1.subn(r'\1\2"[REDACTED_BY_SECURITY_SCANNER]"', content)
    
    # Szukamy kluczy AWS
    pattern2 = re.compile(r'AKIA[A-Z0-9]{16}')
    sanitized, count2 = pattern2.subn(r'"[REDACTED_AWS_KEY]"', sanitized)
    
    has_secrets = (count1 + count2) > 0
    return sanitized, has_secrets

def get_system_prompt(file_path, policy):
    filename = str(file_path).lower()
    if "docker" in filename or "compose" in filename:
        return f"""Jesteś ekspertem DevSecOps. Audytuj plik infrastruktury: {{content}}
        Polityka: {json.dumps(policy)}.
        Zwróć wynik WYŁĄCZNIE jako JSON:
        {{"status": "NON_COMPLIANT", "violations": [{{"issue": "...", "criticality": "HIGH/MEDIUM/LOW", "remediation": "..."}}]}}
        Jeśli plik jest bezpieczny, zwróć {{"status": "COMPLIANT", "violations": []}}"""
    
    return """Jesteś ekspertem bezpieczeństwa kodu. Audytuj ten plik: {content}.
    Zwróć wynik WYŁĄCZNIE jako JSON:
    {"status": "NON_COMPLIANT", "violations": ["lista naruszeń"]}
    Jeśli plik jest bezpieczny, zwróć {"status": "COMPLIANT", "violations": []}"""

def run_security_scan(file_path, policy):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. INTELIGENTNE MASKOWANIE SEKRETÓW
    sanitized_content, has_secrets = redact_secrets_locally(content)

    if has_secrets:
        print(f"[INFO] Wykryto i zamaskowano sekrety w pliku {file_path}. Kontynuuję skanowanie LLM...")

    # 2. Wysyłka oczyszczonego kodu (sanitized_content) do AI
    prompt = get_system_prompt(file_path, policy).replace("{content}", sanitized_content)
    
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-3.5-flash",
                contents=prompt,
            )
            clean_json = response.text.replace('```json', '').replace('```', '').strip()
            result_json = json.loads(clean_json)
            
            # 3. Dodanie lokalnego znaleziska do końcowego raportu z AI
            if has_secrets:
                if result_json.get("status") == "COMPLIANT":
                    result_json["status"] = "NON_COMPLIANT"
                if "violations" not in result_json:
                    result_json["violations"] = []
                # Wpychamy naszą informację na samą górę listy naruszeń
                result_json["violations"].insert(0, "[LOCAL FILTER] Wykryto twardo zapisane hasło/klucz. Wartość zamaskowano przed wysłaniem do LLM.")
                
            return result_json

        except Exception as e:
            error_msg = str(e).lower()
            if "429" in error_msg or "503" in error_msg or "quota" in error_msg:
                print(f"[WARN] Limit API (429/503). Czekam 15s (próba {attempt+1}/3)...")
                time.sleep(15)
                continue
            return {"status": "ERROR", "violations": [f"Błąd API: {e}"]}
            
    return {"status": "ERROR", "violations": ["Przekroczono limit prób API"]}

def save_report(results):
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/scan_{timestamp}.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n[INFO] Raport zapisano w: {report_path}")

if __name__ == "__main__":
    policy = get_security_policy()
    
    targets = []
    examples_path = Path('examples')
    if examples_path.exists():
        targets.extend(examples_path.rglob('*.py'))
        targets.extend(examples_path.rglob('*docker*'))
            
    final_report = {"scan_date": str(datetime.now()), "files": {}}
    
    for target in targets:
        print(f"\n[SCANNING] {target}")
        result = run_security_scan(target, policy)
        final_report["files"][str(target)] = result
        time.sleep(15)

    save_report(final_report)
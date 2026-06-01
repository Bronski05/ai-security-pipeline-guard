import json
import os
import time
from datetime import datetime
from pathlib import Path
from google import genai
from dotenv import load_dotenv

# Załadowanie zmiennych środowiskowych
load_dotenv()
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

def get_security_policy():
    """Wczytuje reguły bezpieczeństwa z pliku JSON."""
    try:
        with open('rules/docker_rules.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"note": "Brak specyficznej polityki. Użyj ogólnych zasad bezpieczeństwa."}

def get_system_prompt(file_path, policy):
    """Zwraca dedykowany prompt w zależności od typu pliku."""
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
    """Przesyła plik do API z obsługą limitów."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    prompt = get_system_prompt(file_path, policy).replace("{content}", content)
    
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
            )
            clean_json = response.text.replace('```json', '').replace('```', '').strip()
            return json.loads(clean_json)
        except Exception as e:
            error_msg = str(e).lower()
            if "429" in error_msg or "503" in error_msg or "quota" in error_msg:
                print(f"[WARN] Limit API (429/503). Czekam 15s (próba {attempt+1}/3)...")
                time.sleep(15)
                continue
            return {"status": "ERROR", "violations": [f"Błąd API: {e}"]}
            
    return {"status": "ERROR", "violations": ["Przekroczono limit prób API"]}

def save_report(results):
    """Zapisuje wyniki do pliku."""
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/scan_{timestamp}.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n[INFO] Raport zapisano w: {report_path}")

if __name__ == "__main__":
    policy = get_security_policy()
    
    # Skanujemy TYLKO folder examples/
    targets = []
    examples_path = Path('examples')
    if examples_path.exists():
        targets.extend(examples_path.rglob('*.py'))
        targets.extend(examples_path.rglob('*docker*'))
            
    print(f"DEBUG: Pliki do przeskanowania: {[str(t) for t in targets]}")
    
    final_report = {"scan_date": str(datetime.now()), "files": {}}
    
    for target in targets:
        print(f"\n[SCANNING] {target}")
        result = run_security_scan(target, policy)
        final_report["files"][str(target)] = result
        time.sleep(15)

    save_report(final_report)
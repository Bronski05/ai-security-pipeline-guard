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
    """Wczytuje reguły z pliku JSON (Policy-as-Code)"""
    with open('rules/docker_rules.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def run_security_scan(dockerfile_path, policy):
    """Przesyła Dockerfile oraz politykę do modelu AI z obsługą błędów 503"""
    with open(dockerfile_path, 'r', encoding='utf-8') as f:
        content = f.read()

    prompt = f"""
    Jesteś inżynierem bezpieczeństwa. Audytuj Dockerfile: {content}
    Zgodnie z polityką: {json.dumps(policy)}.
    Zwróć wynik WYŁĄCZNIE jako obiekt JSON o strukturze:
    {{"status": "COMPLIANT" or "NON_COMPLIANT", "violations": ["lista naruszeń lub pusta lista"]}}
    """
    
    # Mechanizm retry dla błędów 503 (przeciążenie serwera)
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-3.5-flash",
                contents=prompt,
            )
            clean_json = response.text.replace('```json', '').replace('```', '').strip()
            return json.loads(clean_json)
        except Exception as e:
            if "503" in str(e) and attempt < 2:
                print(f"[WARN] Serwer zajęty (503), próba {attempt+1}/3. Czekam {5 * (attempt + 1)}s...")
                time.sleep(5 * (attempt + 1))
                continue
            raise e

def save_report(results):
    """Zapisuje wyniki do folderu reports/"""
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/scan_{timestamp}.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n[INFO] Raport zapisano w: {report_path}")

if __name__ == "__main__":
    policy = get_security_policy()
    # Przeszukiwanie folderu examples w poszukiwaniu wszystkich Dockerfile
    targets = list(Path('examples').rglob('*Dockerfile*'))
    
    final_report = {"scan_date": str(datetime.now()), "files": {}}
    
    for target in targets:
        print(f"\n[SCANNING] {target}")
        try:
            result = run_security_scan(target, policy)
            final_report["files"][str(target)] = result
            print(f"Status: {result['status']}")
        except Exception as e:
            print(f"[ERROR] Nie udało się przeskanować {target}: {e}")

    save_report(final_report)
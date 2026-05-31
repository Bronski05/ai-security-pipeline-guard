import os
from google import genai
from dotenv import load_dotenv

# Konfiguracja
load_dotenv()
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

def audit_code(file_path):
    with open(file_path, 'r') as f:
        code = f.read()

    prompt = f"Jesteś ekspertem SecOps. Przeanalizuj ten Dockerfile i wypisz luki bezpieczeństwa: {code}"
    
    # Używamy modelu z Twojej listy: gemini-3.5-flash
    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
    )
    return response.text

if __name__ == "__main__":
    file_to_check = 'examples/insecure_docker.Dockerfile'
    print(f"--- Skanowanie: {file_to_check} ---")
    try:
        result = audit_code(file_to_check)
        print(result)
    except Exception as e:
        print(f"Wystąpił błąd podczas generowania: {e}")
import pytest
from src.scanner import redact_secrets_locally, run_security_scan

def test_redact_secrets_locally_no_secrets():
    """Test sprawdza, czy bezpieczny kod pozostaje nietknięty przez filtr DLP."""
    clean_code = 'print("Witaj świecie, brak haseł")'
    sanitized, has_secrets = redact_secrets_locally(clean_code)
    assert has_secrets is False
    assert sanitized == clean_code

def test_redact_secrets_locally_with_password():
    """Test sprawdza, czy filtr DLP poprawnie wykrywa i maskuje hasła."""
    risky_code = 'db_password = "super_secret_password_123"'
    sanitized, has_secrets = redact_secrets_locally(risky_code)
    assert has_secrets is True
    assert "[REDACTED_BY_SECURITY_SCANNER]" in sanitized

def test_redact_secrets_locally_with_aws_key():
    """Test sprawdza, czy filtr DLP poprawnie wykrywa i maskuje klucze AWS."""
    risky_code = 'aws_key = "AKIA1234567890ABCDEF"'
    sanitized, has_secrets = redact_secrets_locally(risky_code)
    assert has_secrets is True
    assert "[REDACTED_AWS_KEY]" in sanitized

def test_run_security_scan_local_override(tmp_path):
    """Test sprawdza, czy deterministyczny bezpiecznik nadpisuje status na NON_COMPLIANT."""
    # Tworzymy tymczasowy plik testowy zawierający twardo zapisany sekret
    test_file = tmp_path / "test_credentials.py"
    test_file.write_text('api_key = "AKIA1234567890ABCDEF"', encoding="utf-8")
    
    # Przykładowa pusta polityka
    mock_policy = {"policies": {}}
    
    # Uruchamiamy skan
    result = run_security_scan(str(test_file), mock_policy)
    
    # Asersje zgodne z strukturą Pydantic (lista słowników)
    assert result["status"] == "NON_COMPLIANT"
    assert len(result["violations"]) > 0
    assert "[LOCAL FILTER]" in result["violations"][0]["issue"]
    assert result["violations"][0]["criticality"] == "HIGH"
    assert "remediation" in result["violations"][0]
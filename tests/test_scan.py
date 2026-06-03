import pytest
import sys
import os

# Dodajemy folder src do ścieżki, żeby testy widziały nasz skaner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from scanner import redact_secrets_locally

def test_no_secrets():
    """Test sprawdza, czy czysty kod pozostaje nietknięty."""
    clean_code = 'print("Witaj, tu nie ma haseł")'
    sanitized, has_secrets = redact_secrets_locally(clean_code)
    
    assert has_secrets is False
    assert sanitized == clean_code

def test_password_redaction():
    """Test sprawdza, czy standardowe hasło zostanie poprawnie ukryte."""
    risky_code = 'db_password = "my_super_secret_123"'
    sanitized, has_secrets = redact_secrets_locally(risky_code)
    
    assert has_secrets is True
    assert "[REDACTED_BY_SECURITY_SCANNER]" in sanitized
    assert "my_super_secret_123" not in sanitized

def test_aws_key_redaction():
    """Test sprawdza, czy klucz AWS jest wykrywany i maskowany."""
    risky_code = 'aws_key = "AKIA1234567890ABCDEF"'
    sanitized, has_secrets = redact_secrets_locally(risky_code)
    
    assert has_secrets is True
    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "AKIA1234567890ABCDEF" not in sanitized
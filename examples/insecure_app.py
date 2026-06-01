import sqlite3

# 1. Hardcodowane hasło do bazy
DB_PASSWORD = "super_secret_admin_password_123"

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 2. Krytyczna luka: SQL Injection (łączenie stringów zamiast parametryzacji)
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    return cursor.fetchall()
import sqlite3
import os

def create_auth_data():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authentication (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            salt TEXT,
            hashed TEXT
        )
    ''')

    conn.commit()
    conn.close()

def print_auth_data():

    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'auth_data.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    print(cursor.fetchone())

    conn.close()

create_auth_data()
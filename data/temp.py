#temporary dev database manegement, will be excluded after the project is done

import sqlite3
import os

def create_database():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'database.db')
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER,
                private TEXT,
                public TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                salt TEXT,
                hashed_password
            )
        ''')

        conn.commit()
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def print_database():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_dir, 'database.db')

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        for table in tables:
            print(table)
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

create_database()
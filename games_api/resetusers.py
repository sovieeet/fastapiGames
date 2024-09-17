import sqlite3

def reset_users_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('DROP TABLE IF EXISTS users')
    
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Table 'users' has been reset.")

reset_users_table()

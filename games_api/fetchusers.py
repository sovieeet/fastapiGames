import sqlite3

def fetch_all_users():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    if users:
        for user in users:
            print(dict(user))
    else:
        print("No users found")
    
    conn.close()

fetch_all_users()

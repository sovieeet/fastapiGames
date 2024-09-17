import sqlite3

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_users_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                    );''')
    conn.commit()
    conn.close()

def create_videogames_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS videogames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    release_year INTEGER NOT NULL,
                    developer TEXT NOT NULL,
                    image_url TEXT NOT NULL
                    );''')
    conn.commit()
    conn.close()

create_users_table()
create_videogames_table()
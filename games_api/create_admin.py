from security import get_password_hash
from database import get_db_connection

def create_first_admin():
    conn = get_db_connection()
    hashed_password = get_password_hash("admin")
    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                 ("admin", hashed_password, "admin"))
    conn.commit()
    conn.close()
    print("Admin user created successfully!")

create_first_admin()
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('users.db')

cursor = conn.cursor()

# Create Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
''')

# Delete old users
cursor.execute("DELETE FROM users")

# Hashed Password
hashed_password = generate_password_hash("admin123")

# Insert Secure User
cursor.execute('''
INSERT INTO users (username, password)
VALUES (?, ?)
''', ("admin", hashed_password))

conn.commit()
conn.close()

print("Secure Database Created Successfully")
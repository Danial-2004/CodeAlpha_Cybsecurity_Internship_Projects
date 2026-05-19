import sqlite3

conn = sqlite3.connect('users.db')

cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
''')

# Demo user
cursor.execute('''
INSERT INTO users (username, password)
VALUES ('admin', 'admin123')
''')

conn.commit()
conn.close()

print("Database Created Successfully")
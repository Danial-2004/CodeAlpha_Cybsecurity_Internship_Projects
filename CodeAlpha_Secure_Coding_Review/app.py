from flask import Flask, request

import sqlite3

app = Flask(__name__)

# Home Page
@app.route('/')
def home():
    return '''
    <h2>Vulnerable Login System</h2>

    <form method="POST" action="/login">
        Username:<br>
        <input type="text" name="username"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        <input type="submit" value="Login">
    </form>
    '''

# Vulnerable Login Route
@app.route('/login', methods=['POST'])
def login():

    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SQL Injection Vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    cursor.execute(query)

    user = cursor.fetchone()

    if user:
        return "Login Successful"

    return "Invalid Credentials"

if __name__ == '__main__':
    app.run(debug=True)
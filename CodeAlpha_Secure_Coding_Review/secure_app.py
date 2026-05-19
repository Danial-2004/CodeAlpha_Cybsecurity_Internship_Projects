from flask import Flask, request
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

app = Flask(__name__)

# Home Page
@app.route('/')
def home():

    return '''
    <h2>Secure Login System</h2>

    <form method="POST" action="/login">

        Username:<br>
        <input type="text" name="username"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        <input type="submit" value="Login">

    </form>
    '''

# Secure Login Route
@app.route('/login', methods=['POST'])
def login():

    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Parameterized Query
    query = "SELECT password FROM users WHERE username=?"

    cursor.execute(query, (username,))

    result = cursor.fetchone()

    conn.close()

    # Password Hash Verification
    if result and check_password_hash(result[0], password):
        return "Login Successful"

    return "Invalid Credentials"

if __name__ == '__main__':

    # Debug Disabled
    app.run(debug=False)
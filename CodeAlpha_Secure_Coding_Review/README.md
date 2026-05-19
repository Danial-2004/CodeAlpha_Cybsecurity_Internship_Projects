Project Title
# Secure Coding Review using Python Flask

Objective
This project demonstrates a secure coding review of a vulnerable Flask login application.
The project identifies common security vulnerabilities and applies remediation techniques using secure coding practices.

Tools Used
- Python
- Flask
- Bandit
- SQLite
- OWASP Top 10

Vulnerabilities Identified
- SQL Injection
- Weak Password Storage
- Debug Mode Enabled
- Missing Input Validation
- Cross-Site Scripting (XSS)
- Insecure File Upload

Security Fixes Applied
- Parameterized Queries
- Password Hashing
- Secure Error Handling
- Debug Mode Disabled
- Input Validation

How to Run
## Install Requirements

pip install -r requirements.txt

## Run Vulnerable App

python app.py

## Run Secure App

python secure_app.py
Bandit Scan
bandit -r app.py
Author
Muhammad Danial Haider
Cybersecurity Internship Project
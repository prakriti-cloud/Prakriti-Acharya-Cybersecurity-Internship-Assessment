**Task 1**  
I used Kali-Linux installed in my VM for the given tasks. Docker was not installed yet. So first of all, I needed to install it. And after installing it, I enabled docker, then I ran the provided command to open the juice-shop website. Upon researching more deeply, I found out that juice-shop is the most modern and sophisticated insecure application used for security trainings, awareness demos, and CTFs. It is like a guinea pig for security tools for cybersecurity professionals. After running the command: docker run –rm -p 3000:3000 bkimminich/juice-shop
I opened the browser (Mozilla Firefox) and navigated to the juice-shop website with the URL: http://localhost:3000.  
Now, I tried to log in as an admin in order to know whether the website has a vulnerability in its log in page. While logging in as an admin, I found the following vulnerability:
Vulnerability Type: SQL Injection (Authentication Bypass)  
Target Endpoint: /rest/user/login  
Payload used: ' OR 1=1 –  
**Explanation:**  
The application constructs its SQL queries by directly concatenating raw user input rather than using parameterized queries. The payload breaks out of the expected data string, injects an always-true logical condition (OR 1=1), and instructs the database to ignore the remainder of the query (--). This causes the authentication statement to evaluate to TRUE without requiring a valid password, logging the user in as the first record in the database table (the Administrator).
Exploiting the SQL injection vulnerability bypassed authentication and granted administrative privileges (admin@juice-sh.op). This exposed restricted data including internal user profiles, system administration controls, customer feedback logs, and cross-user order details that are strictly hidden from standard unauthenticated users. With such privilege, I realized that I could use those customers data and feedback in any way I wanted to.

**Task 2**  
The attacker’s IP address is: 185.220.101.47  
Secondary Reconnaissance IP: 45.83.64.12  
Total Failed Attempts: ~200 + SSH password Attempts  
Targeted Accounts:  
Deploy (120+ failed attempts before succeeding)  
Root (40+ attempts)  
Admin  
User, postgres, git, ftp, oracle, pi, guest, test  
A login attempt succeeded at 14:09:10 from 185.220.101.47 into deploy user account via password:  
<img width="865" height="43" alt="Task2-Successful Login Attempt (Part1)" src="https://github.com/user-attachments/assets/434d56d6-e788-40b6-8a32-2c70fcfc8c56" />  
Attacker’s Actions Post-Compromise:  
**Privilege Escalation/Data Theft (14:09:50):** Ran sudo /usr/bin/cat /etc/shadow to dump system password hashes.  
**Persistent Creation (14:10:45):** Created a backdoor user account called sysupdate.  
**Privilege Escalation for Backdoor (14:11:00):** Added sysupdate to the sudo group (sudo /usr/sbin/usermod/ -aG sudo sysupdate).  
**Session Termination (14:15:10):** Logged out of the deploy session after establishing persistence.  
**Two Defensive Controls to Prevent/Detect This Attack**  
**Fail2ban (Automated IP Blocking):**  
**Simple Analogy:** Imagine a nightclub bouncer who keeps an eye on the door. If someone tries to guess the secret password and gets it wrong 5 times in a row, the bouncer immediately kicks them out and locks the gate so they can't try again.  
**How it helps us:** In our case, the hacker tried over 100 wrong passwords in just a few minutes. Fail2ban would have noticed this after the first 5 wrong tries and blocked the hacker's internet address (IP) right away—stopping them long before they ever guessed the right password for the deploy account.   
**Enforcing SSH Key-Based Authentication & Disable Password Authentication:**  
**Simple Analogy:** Instead of telling the door guard a text password (which anyone can try to guess), you hand the guard a physical, custom-cut key card that only you possess. If someone tries to shout out passwords at the door, the guard ignores them completely because only a real physical key works.  
**How it helps us:** By turning off password logins on the server, we force everyone to use these secure "digital key cards" (SSH keys). Because a hacker can't "guess" a physical key card, their entire brute-force attack becomes completely useless. (Notice how the real sysadmin logged in using key cards at 08:39 and 12:49 safely without any issues).

**Task 3**  
The vulnerability in this code is SQL Injection. In the original code, the query string is created by inserting the user's input directly into the SQL string using Python's string formatting (f"..."):  
# VULNERABLE CODE  
query = (  
    "SELECT id, username, role FROM users "  
    f"WHERE username = '{username}' AND password_hash = '{password_hash}'"  
)  
Because the input is directly stitched into the SQL string, an attacker can input special characters (like ' OR 1=1 --) into the username field. The database gets tricked into treating that text as actual SQL command logic rather than plain text, bypassing authentication without a valid password.   
**The Fixed Secure Code**  
To fix this vulnerability, we should replace dynamic string concatenation with a Parameterized Query (using ? placeholders). This forces the database engine to treat user input strictly as plain data values, making SQL injection impossible.   
The updated version is as follows:  
import hashlib  
import sqlite3  
from flask import Flask, request, jsonify  
app = Flask(__name__)  
DB_PATH = "users.db"  
def get_db():  
    conn = sqlite3.connect(DB_PATH)  
    conn.row_factory = sqlite3.Row  
    return conn  
@app.route("/login", methods=["POST"])  
def login():  
    username = request.form.get("username", "")  
    password = request.form.get("password", "")  
    password_hash = hashlib.sha256(password.encode()).hexdigest()  
    # SECURE FIX: Using '?' placeholders for parameterized queries  
    query = (  
        "SELECT id, username, role FROM users "  
        "WHERE username = ? AND password_hash = ?"  
    )  
    conn = get_db()  
    # Pass inputs as a tuple in execute() so the driver safely handles them  
    user = conn.execute(query, (username, password_hash)).fetchone()  
    conn.close()  
    if user is None:  
        return jsonify({"error": "Invalid username or password"}), 401  
    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"]})  
if __name__ == "__main__":  
    app.run(port=5000)  
**Explanation**  
**Analogy:** Imagine filling out a physical job application form.  
•	The vulnerable code takes whatever you write on the line and reads it as a brand-new rule in the company handbook.  
•	The fixed code treats your writing strictly as text inside a restricted form field box—no matter what you write inside that box, it will never be treated as a company rule.  
**Why parameterization works:** By passing (username, password_hash) as parameters separately to execute(), SQLite safely escapes all quotes and special characters automatically.  






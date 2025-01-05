import os
import sqlite3
from flask_bcrypt import Bcrypt
from flask import Flask, redirect, url_for, request, render_template, send_from_directory, flash, session

app = Flask(__name__)
app.secret_key = "abcdefg"
bcrypt = Bcrypt(app)

def validate_password(password):
    if len(password) < 8 or len(password) > 25:
        return "Your password must be at 8 characters long and 25 characters short."
    if not any(char.isdigit() for char in password):
        return "Your password must contain at least 1 number."
    if not any(char.isupper() for char in password):
        return "Your password must contain at lease 1 upper case letter."
    if not any(char in "!@#$%^&*()_+-=<>?/|[]~,." for char in password):
        return "Your password must contain at least one special character. Examples: (!@#$%^&*()_+-=<>?/|[]~,.)"
    return None

def init_db():
    with sqlite3.connect("userdata.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        print("Userdata database initialized.")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        error = validate_password(password)
        if error:
            flash(error, "error")
            return render_template("register.html")
        
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8") #hash password this line

        try:
            with sqlite3.connect("userdata.db") as conn:
                conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
                conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Username or E-mail already exists. Please choose another one.", "error")
            return render_template("register.html")

    return render_template("register.html")

@app.route("/login", methods = ['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with sqlite3.connect("userdata.db") as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username, )).fetchone()

        if user and bcrypt.check_password_hash(user[3], password):
            session["user_id"] = user[0]
            flash("Login successful!", "success")
            return redirect("/")
        else:
            flash("Invalid username or password", "error")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/")
def main():
    if "user_id" in session:
        return f"Welcome, User {session['user_id']}! <a href='/logout'>Logout</a>"
    return "Welcome! <a href='/login'>Log in</a> or <a href='/register'>Register</a>"

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.", "info")
    return redirect("/")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configuring database connection
complaints = sqlite3.connect("complaints.db", check_same_thread=False)
db = complaints.cursor()

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET"])
@login_required
def index():
    usercomplaints = db.execute("SELECT * FROM complaints WHERE userid = ?", (session["user_id"],)).fetchall()
    return render_template("index.html", name = session["username"], usercomplaints = usercomplaints)

@app.route("/complaint", methods=["GET", "POST"])
@login_required
def complaint():
    if request.method == "POST":
        db.execute("INSERT INTO complaints (userid, hostel, complaint, type, date, rollnum, mobilenum) VALUES(?, ?, ?, ?, date(), ?, ?)", (session["user_id"], request.form.get("hostels"), request.form.get("complaint"), request.form.get("type"), request.form.get("rollnum"), request.form.get("mobnum")))
        complaints.commit()
        return redirect("/submit")
    else:
        return render_template("complaint.html", name = session["username"])

@app.route("/submit", methods=["GET"])
@login_required
def submit():
        return render_template("submitted.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

         # Query database for username and ensure it is not already taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),)).fetchall()
        if len(rows) != 0:
            return apology("username already taken", 400)

        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (username, hash))
        complaints.commit()

        # Log the new user in
        rows = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
        session["user_id"] = rows[0][0]
        session["username"] = rows[0][1]

        # Redirect user to home page
        return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),)).fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]
        session["username"] = rows[0][1]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/pwdchange", methods=["GET", "POST"])
@login_required
def pwdchange():
    """Change password"""
    if request.method == "POST":

        oldpasswordhash = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchall()[0][2]

        # Ensure form was submitted correctly
        if (not request.form.get("oldpassword")) or (not request.form.get("newpassword")) or (not request.form.get("confirmnewpassword")):
            return apology("must fill all boxes", 403)

        # Ensure passwords match
        elif request.form.get("newpassword") != request.form.get("confirmnewpassword"):
            return apology("new passwords must match", 403)

        elif not check_password_hash(oldpasswordhash, request.form.get("oldpassword")):
            return apology("enter old password correctly", 403)

        hash = generate_password_hash(request.form.get("newpassword"), method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", (hash, session["user_id"]))
        complaints.commit()

        # Redirect user to home page
        return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("pwdchange.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

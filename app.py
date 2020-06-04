from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
import sqlite3 as sql
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helper import login_required


app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            print("No username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            print("No password")

        # Query database for username
        username=request.form.get("username")
        con = sql.connect("database.db")
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        rows = cur.fetchall();
        print(rows[0]["id"])

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            print("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
      error = None
      try:
        # Store password
        password = request.form.get("password")
        username = request.form.get("username")

        # Ensure username was submitted
        if not username:
            error = "Please provide a username"
            return render_template("register.html", error=error)
        
        # Check is username is already taken
        is_new = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        # if len(is_new) == 1:
        #     return

        # Ensure password was submitted
        if not password:
            print("no passowrd")

        # Check if password is long enough, has a letter and a number init
        elif len(password) < 5:
            print("Password has less than 5 charecters.")
        elif re.search('[0-9]', password) is None:
            print("Passowrd must have a number.")
        elif re.search('[A-Z]', password) is None:
            print("Password must have at least one capital letter.")

        # Ensure the user writes correct password confirmation
        if not password == request.form.get("confirm_password"):
            print("Passwords are not matching")

        # Hash the password
        hash = generate_password_hash(password)

        # Insert user into the database
        with sql.connect("database.db") as con:
            print(username)
            db = con.cursor()
            user_id = db.execute("INSERT INTO users (username, password) VALUES (:username, :hash)", (username, hash))
            con.commit()
      except:
         con.rollback()
         error = "Something went wrong"
         return render_template("login.html", error=error)
      finally:
         flash('You successfully signed up')
         return render_template("index.html")
         con.close()


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route('/users')
def list():
   con = sql.connect("database.db")
   con.row_factory = sql.Row
   
   cur = con.cursor()
   cur.execute("select * from users")
   
   rows = cur.fetchall();
   print(rows)
   return render_template("list.html",rows = rows)

if __name__ == '__main__':
   app.run(debug = True)


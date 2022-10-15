import os
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, session, redirect, render_template, request, url_for, jsonify
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from helpers import validate_email, validate_password, validate_username, sendmail
import random
import requests
import envs

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

@app.route("/", methods=["POST", "GET"])
def index():    
    if session.get("username") == None:
        return redirect("/login")

    if request.method == "GET":
        return render_template("homepage.html", username=session["username"])
    
    keyword = request.form.get("keyword")
    searchtype = request.form.get("searchtype")
    if not keyword or not searchtype:
        return render_template("homepage.html", username=session["username"], search_error="enter a keyword and select type")

    if searchtype == "isbn":
        books = db.execute("SELECT * FROM books WHERE isbn LIKE :isbn", {"isbn": f"%{keyword}%"}).fetchall()
        if books == []:
            return render_template("homepage.html", username=session["username"], search_error="Sorry, we couldn't find any match.")
        else:
            return render_template("homepage.html", username=session["username"], books=books)
    elif searchtype == "title":
        keyword = keyword.title()
        books = db.execute("SELECT * FROM books WHERE title LIKE :title", {"title": f"%{keyword}%"}).fetchall()
        if books == []:
            return render_template("homepage.html", username=session["username"], search_error="Sorry, we couldn't find any match.")
        else:
            return render_template("homepage.html", username=session["username"], books=books)
    elif searchtype == "author":        
        books = db.execute("SELECT * FROM books WHERE author LIKE :author", {"author": f"%{keyword}%"}).fetchall()
        if books == []:
            return render_template("homepage.html", username=session["username"], search_error="Sorry, we couldn't find any match.")
        else:
            return render_template("homepage.html", username=session["username"], books=books)
    else:
        return redirect("/")

@app.route("/api/<string:isbn>")
def book_api(isbn):
    if session.get("username") == None:
        return redirect("/login")
    
    book = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchone()    
    if book == None:
        return jsonify({"error": "Invalid ISBN Number"}), 404
    
    r = []    
    ratings = db.execute("SELECT * FROM reviews WHERE book_id = :book_id", {"book_id": book.id}).fetchall()
    if ratings == []:
        l = 0
        avg = 0
    else:
        for rating in ratings:
            r.append(rating.rating)        
        l = len(r)
        avg = sum(r)/l

    return jsonify({"title": book.title, "author": book.author, "year": book.year, "isbn": book.isbn, "review_count": l, "average_score": avg})


@app.route("/book/<int:id>", methods=["POST", "GET"])
def book(id):
    if session.get("username") == None:
        return redirect("/login")
    
    book = db.execute("SELECT * FROM books WHERE id = :id", {"id": id}).fetchone()
    reviews = db.execute("SELECT * FROM reviews WHERE book_id = :book_id AND username != :username", {"book_id": id, "username": session["username"]}).fetchall()    
    user_review = db.execute("SELECT * FROM reviews WHERE book_id = :book_id AND username = :username", {"book_id": id, "username": session["username"]}).fetchone()
    
    key = envs.key
    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": key, "isbns": book.isbn})
    if res.status_code != 200:
        l = None
    else:
        r = res.json()
        l = r["books"][0]

    if request.method == "GET":
        return render_template("book.html", username=session["username"], book=book, reviews=reviews, user_review=user_review, goodread=l)
    
    if user_review != None:
        return redirect(url_for('book', id=id))

    comment = request.form.get("comment")
    rating = request.form.get("rating")

    if not comment or not rating:
        return render_template("book.html", username=session["username"], book=book, reviews=reviews, user_review=user_review, review_error="Type your review and select a rating.", goodread=l)
    
    try:
        rating = int(rating)
    except ValueError:
        return render_template("book.html", username=session["username"], book=book, reviews=reviews, user_review=user_review, review_error="invalid rating", goodread=l)

    db.execute("INSERT INTO reviews (rating, comment, book_id, username) VALUES (:rating, :comment, :book_id, :username)", {"rating": rating, "comment": comment, "book_id": id, "username": session["username"]})
    db.commit()
    return redirect(url_for('book', id=id))


@app.route("/deletereview/<int:id>")
def deletereview(id):
    if session.get("username") == None:
        return redirect("/login")

    db.execute("DELETE FROM reviews WHERE book_id = :book_id AND username = :username", {"book_id": id, "username": session["username"]})
    db.commit()
    return redirect(url_for('book', id=id))

@app.route("/editreview/<int:id>", methods=["POST", "GET"])
def editreview(id):
    if session.get("username") == None:
        return redirect("/login")

    book = db.execute("SELECT * FROM books WHERE id = :id", {"id": id}).fetchone()
    review = db.execute("SELECT * FROM reviews WHERE book_id = :book_id AND username = :username", {"book_id": id, "username": session["username"]}).fetchone()

    if request.method == "GET":
        return render_template("editreview.html", username=session["username"], review=review, book=book)

    comment = request.form.get("comment")
    rating = request.form.get("rating")

    if not comment or not rating:
        return render_template("editreview.html", username=session["username"], edit_review_error="Type your review and select a rating.", review=review, book=book)

    try:
        rating = int(rating)
    except ValueError:
        return render_template("editreview.html", username=session["username"], edit_review_error="incorrect rating", review=review, book=book)
    
    db.execute("UPDATE reviews SET comment = :comment WHERE book_id = :book_id AND username = :username", {"comment": comment, "book_id": id, "username": session["username"]})
    db.execute("UPDATE reviews SET rating = :rating WHERE book_id = :book_id AND username = :username", {"rating": rating, "book_id": id, "username": session["username"]})
    db.commit()
    return redirect(url_for('book', id=id))


@app.route("/login", methods=["POST", "GET"])
def login():
    if session.get("username") != None:
        return redirect("/")

    if request.method == "GET":
        return render_template("login.html")
    
    session.clear()
    
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return render_template("login.html", login_error="enter username and password")
    
    user = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchone()
    if user == None:
        user = db.execute("SELECT * FROM users WHERE email = :username", {"username": username}).fetchone()
        if user == None:
            return render_template("login.html", login_error="Incorrect username/email address")
    
    if check_password_hash(user.password, password):
        session["username"] = user.username
        session["user_id"] = user.id
        return redirect("/")
    else:
        return render_template("login.html", login_error="Incorrect password")


@app.route("/register", methods=["POST", "GET"])
def register():
    if session.get("username") != None:
        return redirect("/")
        
    if request.method == "GET":
        return render_template("register.html")

    session.clear()

    name = request.form.get("name")
    mobile = request.form.get("mobile")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    password1 = request.form.get("password1")

    if not name or not username or not email or not email or not password or not password1:
        return render_template("register.html", reg_error="enter all fields marked with *")

    if password != password1:
        return render_template("register.html", reg_error="passwords don't match")

    if not validate_email(email):
        return render_template("register.html", reg_error="please enter a valid email address")
    if not validate_password(password):
        return render_template("register.html", reg_error="enter an alpha-numeric password, minimum six characters long")
    if not validate_username(username):
        return render_template("register.html", reg_error="only alpha-numeric and '.', '-', '_' characters allowed in username")

    username.strip()
    email.strip()
    name = name.title()

    user = db.execute("SELECT * FROM users WHERE email = :email",{"email": email}).fetchone()
    if user != None:
        return render_template("register.html", reg_error="This email is registered with a different account.")

    user = db.execute("SELECT * FROM users WHERE username = :username",{"username": username}).fetchone()
    if user != None:
        return render_template("register.html", reg_error="This Username is already taken. Select a different Username.")

    password = generate_password_hash(password)
    if not mobile:
        mobile = None
    code = str(random.randint(100000, 999999))
    session["userInfo"] = {"name": name, "username": username, "mobile": mobile, "email": email, "password": password, "code": code}
    try:
        sendmail(email, "Verify Email", code)
    except:
        return redirect("/no_verification")
    
    return redirect("/verification")

@app.route("/verification", methods=["POST", "GET"])
def verification():
    if session.get("userInfo") == None:
        return redirect("/")

    if request.method == "GET":
        return render_template("verification.html", email=session["userInfo"]["email"])
    code = request.form.get("code")
    if not code:
        return render_template("verification.html", email=session["userInfo"]["email"], verification_error="enter verification code")
    if code != session["userInfo"]["code"]:
        return render_template("verification.html", email=session["userInfo"]["email"], verification_error="incorrect verification code")
    db.execute("INSERT INTO users (name, mobile, username, email, password) VALUES (:name, :mobile, :username, :email, :password)", {"name": session['userInfo']['name'], "username": session['userInfo']['username'], "mobile": session['userInfo']['mobile'], "email": session['userInfo']['email'], "password": session['userInfo']['password']})
    db.commit()
    email = session["userInfo"]["email"]
    session.clear()
    try:
        sendmail(email, "Registration Successful", "You are now registered with Book Review")
    except:
        return redirect("/login")
    
    return redirect("/login")

@app.route("/no_verification")
def no_verification():
    if session.get("userInfo") == None:
        return redirect("/")

    db.execute("INSERT INTO users (name, mobile, username, email, password) VALUES (:name, :mobile, :username, :email, :password)", {"name": session['userInfo']['name'], "username": session['userInfo']['username'], "mobile": session['userInfo']['mobile'], "email": session['userInfo']['email'], "password": session['userInfo']['password']})
    db.commit()    
    session.clear()
    return redirect("/login")


@app.route("/resend_verification_code")
def resend_verification_code():
    if session.get("userInfo") == None:
        return redirect("/")

    code = str(random.randint(100000, 999999))
    try:
        sendmail(session["userInfo"]["email"], "Verify Email", code)
    except:
        return redirect("/no_verification")
    session["userInfo"]["code"] = code
    return redirect("/verification")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/forgotpassword", methods=["POST", "GET"])
def forgotpassword():
    if session.get("username") != None:
        return redirect("/")
    
    session.clear()
    
    if request.method == "GET":        
        return render_template("forgotpassword.html")

    username = request.form.get("username")
    if not username:
        return render_template("forgotpassword.html", fp_error="enter your username or email address")

    user = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchone()
    if user == None:
        user = db.execute("SELECT * FROM users WHERE email = :username", {"username": username}).fetchone()
        if user == None:
            return render_template("forgotpassword.html", fp_error="Incorrect username or email address")
    
    code = str(random.randint(100000, 999999))
    session["fp_code"] = code
    session["fp_user"] = user
    try:
        sendmail(user.email, "Verify Your Email Address", code)
    except:
        return "EMAIL AUTHENTICATION ERROR"
    
    return redirect("/fp_verification")

@app.route("/fp_verification", methods=["POST", "GET"])
def fp_verification():
    if session.get("fp_code") == None or session.get("fp_user") == None:
        return redirect("/forgotpassword")

    if session.get("username") != None:
        return redirect("/")

    if request.method == "GET":
        return render_template("fp_verification.html", email = session["fp_user"].email)
    code = request.form.get("code")
    if not code:
        return render_template("fp_verification.html", email = session["fp_user"].email, fp_verification_error="enter verification code")
    if code != session["fp_code"]:
        return render_template("fp_verification.html", email = session["fp_user"].email, fp_verification_error="incorrect verification code")
    
    username = session["fp_user"].username
    session.clear()
    session["username"] = username
    return redirect("/change_password")

@app.route("/change_password", methods=["POST", "GET"])
def change_password():
    if session.get("username") == None:
        return redirect("/login")
    
    if request.method == "GET":
        return render_template("change_password.html", username = session["username"])
    
    password = request.form.get("password")
    password1 = request.form.get("password1")
    if not password or not password1:
        return render_template("change_password.html", username = session["username"], fp_change_error="type and confirm new password")

    if password != password1:
        return render_template("change_password.html", username = session["username"], fp_change_error="passwords don't match")

    if not validate_password(password):
        return render_template("change_password.html", username = session["username"], fp_change_error="enter an alpha-numeric password, minimum six characters long")

    password = generate_password_hash(password)
    db.execute("UPDATE users SET password = :password WHERE username = :username", {"password": password, "username": session["username"]})
    db.commit()
    user = db.execute("SELECT * FROM users WHERE username = :username", {'username': session["username"]}).fetchone()
    try:
        sendmail(user.email, "Security Information", "Your password was just changed.")
    except:
        pass
    
    return redirect("/")


@app.route("/resend_fp_verification_code")
def resend_fp_verification_code():
    if session.get("fp_code") == None or session.get("fp_user") == None:
        return redirect("/forgotpassword")

    if session.get("username") != None:
        return redirect("/")

    code = str(random.randint(100000, 999999))
    session["fp_code"] = code
    try:
        sendmail(session["fp_user"].email, "Verify Your Email Address", code)
    except:
        return "EMAIL AUTHENTICATION ERROR"
    return redirect("/fp_verification")


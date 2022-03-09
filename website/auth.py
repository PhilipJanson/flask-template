from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully", category="success")
                login_user(user, remember=True)

                return redirect(url_for("views.home"))
            else:
                flash("Incorrect password", category="error")
        else:
            flash("Username does not exist", category="error")

    return render_template("login.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_repeat = request.form.get("repeatPassword")

        user = User.query.filter_by(username=username).first()

        if user:
            flash("Username is taken", category="error")
        elif len(username) == 0:
            flash("Invalid username", category="error")
        elif len(password) < 5:
            flash("Password must be atleast 5 characters", category="error")
        elif password != password_repeat:
            flash("Passwords do not match", category="error")
        else:
            new_user = User(username=username, password=generate_password_hash(
                password, method="sha256"))
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user, remember=True)
            flash("Account created", category="success")

            return redirect(url_for("views.home"))

    return render_template("signup.html", user=current_user)

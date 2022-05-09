import uuid
from flask_login import login_user, logout_user

from . import db
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():
    name = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(name=name).first()

    if user:
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    new_user = User(public_id=str(uuid.uuid4()),
                    name=name,
                    password=generate_password_hash(password, method='sha256'),
                    admin=False)

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/login', methods=['POST'])
def login_post():
    name = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(name=name).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    return redirect(url_for('main.chat'))


@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

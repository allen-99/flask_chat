#!/usr/bin/env python

from flask import (
    Flask,
    request,
    redirect,
    abort,
    render_template,
    session,
    url_for
)
from flask_sqlalchemy import SQLAlchemy
# /Users/allen_99/DataGripProjects/test/identifier.sqlite

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/allen_99/chat.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(140))
    user_id = db.Column(db.Integer)
    user_name = db.Column(db.String(50))


@app.route('/user', methods=['GET'])
def get_users():
    return 'hello'


@app.route('/user/<user_id>', methods=['GET'])
def get_one_user():
    return 'one user'


@app.route('/user', methods=['POST'])
def create_user():
    return ''


@app.route('/user/<user_id>', methods=['PUT'])
def promote_user():
    return ''


@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user():
    return ''

if __name__ == '__main__':
    app.run(debug=True)

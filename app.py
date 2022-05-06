#!/usr/bin/env python

from flask import (
    Flask,
    request,
    jsonify,
    make_response
)
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from functools import wraps
import jwt
import datetime

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
    admin = db.Column(db.Boolean)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(140))
    user_id = db.Column(db.Integer)
    user_name = db.Column(db.String(50))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'permission denied'})
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'permission denied'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'no users'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'permission denied'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'],
                    password=hashed_password,
                    admin=data['admin'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'new user is here'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'permission denied'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'no users'})

    user.admin = True
    db.session.commit()
    return jsonify({'message': 'now user is admin'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'permission denied'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'no users'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'user deleted'})


@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/chat', methods=['GET'])
@token_required
def get_all_messages(current_user):
    return ''


@app.route('/chat/<message_id>', methods=['GET'])
@token_required
def get_one_message(current_user, message_id):
    return ''


@app.route('/chat/', methods=['POST'])
@token_required
def create_message(current_user):
    data = request.json()

    new_message = Message(text=data['text'], user_id=current_user.public_id, user_name=current_user.name)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'message created'})


@app.route('/chat/<message_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, message_id):
    return ''


@app.route('/hello', methods=['GET'])
def hello():
    return 'hello'


if __name__ == '__main__':
    app.run(debug=True)

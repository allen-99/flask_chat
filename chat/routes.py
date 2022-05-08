from flask import (
    request,
    current_app,
    jsonify,
    make_response,
    Blueprint
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from functools import wraps
import jwt
import datetime
import uuid


from chat import db
from chat.models import User, Message

main_routes = Blueprint("main", __name__,  url_prefix='/')
# , template_folder="templates"


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'token is missing'})

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorated


@main_routes.route('/user', methods=['GET'])
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


@main_routes.route('/user/<public_id>', methods=['GET'])
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


@main_routes.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    user = User.query.filter_by(name=data['name']).first()
    if user:
        return jsonify({'user': 'wrong login'})

    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'],
                    password=hashed_password,
                    admin=data['admin'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'new user is here'})


@main_routes.route('/user/<public_id>', methods=['PUT'])
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


@main_routes.route('/user/<public_id>', methods=['DELETE'])
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


@main_routes.route('/login', methods=['GET'])
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
                           current_app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@main_routes.route('/chat', methods=['GET'])
@token_required
def get_all_messages(current_user):
    messages = Message.query.all()

    output = []

    for message in messages:
        message_data = {}
        message_data['id'] = message.id
        message_data['text'] = message.text
        message_data['user_id'] = message.user_id
        message_data['user_name'] = message.user_name
        output.append(message_data)

    return jsonify({'messages from users': output})


@main_routes.route('/chat/<message_id>', methods=['GET'])
@token_required
def get_one_message(current_user, message_id):
    message = Message.query.filter_by(id=message_id, user_id=current_user.public_id).first()

    if not message:
        return jsonify({'message': 'no message'})

    message_data = {}
    message_data['id'] = message.id
    message_data['text'] = message.text
    message_data['user_id'] = message.user_id
    message_data['user_name'] = message.user_name

    return jsonify({'message': message_data})


@main_routes.route('/chat', methods=['POST'])
@token_required
def create_message(current_user):
    data = request.get_json()

    new_message = Message(text=data['text'], user_id=current_user.public_id, user_name=current_user.name)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'message created'})


@main_routes.route('/chat/<message_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, message_id):
    message = Message.query.filter_by(id=message_id, user_id=current_user.public_id).first()

    if not message:
        return jsonify({'message': 'no message for delete'})

    db.session.delete(message)
    db.session.commit()
    return jsonify({'message': 'message was deleted'})


@main_routes.route('/hello', methods=['GET'])
def hello():
    return 'hello'

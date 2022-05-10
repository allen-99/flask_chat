from flask import Blueprint, render_template, request
from chat.models import Message
from flask_login import login_required, current_user
import uuid
from . import db
main = Blueprint('main', __name__)


@main.route('/chat', methods=['GET'])
@login_required
def chat():

    messages = Message.query.all()
    output = []

    for message in messages:
        message_data = {}
        message_data['id'] = message.id
        message_data['text'] = message.text
        message_data['user_id'] = message.user_id
        message_data['user_name'] = message.user_name
        output.append(message_data)

    return render_template('chat.html', name=current_user.name, messages=messages)


@main.route('/chat', methods=['POST'])
@login_required
def chat_send():
    if request.form.get('message_text') != '':
        new_message = Message(
            text=request.form.get('message_text'),
            user_name=current_user.name,
            user_id=current_user.public_id
        )
        db.session.add(new_message)
        db.session.commit()

    messages = Message.query.all()
    output = []

    for message in messages:
        message_data = {}
        message_data['id'] = message.id
        message_data['text'] = message.text
        message_data['user_id'] = message.user_id
        message_data['user_name'] = message.user_name
        output.append(message_data)

    return render_template('chat.html', name=current_user.name, messages=messages)


@main.route('/profile')
@login_required
def your_chat():
    return render_template('chat.html', name=current_user.name, messages=messages)


from flask import Blueprint, render_template
from chat.models import Message
from flask_login import login_required, current_user

main = Blueprint('main', __name__)


@main.route('/')
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


@main.route('/profile')
@login_required
def your_chat():
    return render_template('chat.html', name=current_user.name)


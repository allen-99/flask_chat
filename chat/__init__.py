from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from chat.сonfig import Configuration

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Configuration)
    db.init_app(app)

    from chat.models import User, Message
    from chat.routes import main_routes

    app.register_blueprint(main_routes)
    return app

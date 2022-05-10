from chat import db
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_login import UserMixin


class User(UserMixin, db.Model):
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


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=5, max=80)],
        render_kw={"placeholder": "Name"},
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=5, max=80)],
        render_kw={"placeholder": "Password"},
    )
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    name = StringField(
        validators=[InputRequired(), Length(min=4, max=80)],
        render_kw={"placeholder": "name"},
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=80)],
        render_kw={"placeholder": "Password"},
    )

    submit = SubmitField("Register")

    def validate_check(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username or email already exists. Please choose a different one."
            )

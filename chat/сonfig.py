import os


class Configuration(object):
    file_path = os.path.abspath(os.getcwd()) + "/chat.db"
    SECRET_KEY = "SECRETKEY"
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + file_path

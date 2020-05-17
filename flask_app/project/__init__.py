from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

db = SQLAlchemy()


def create_app():
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        from . import routes
        db.create_all()
        return app

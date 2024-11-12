from db import db  # Import db from db.py
from flask_login import UserMixin  # Import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)  # Add is_active attribute

    def __repr__(self):
        return f'<User {self.username}>'

    # Flask-Login requires these methods, but UserMixin already provides them:
    # is_authenticated, is_anonymous, get_id
    # You can override them if needed, but UserMixin provides default implementations.

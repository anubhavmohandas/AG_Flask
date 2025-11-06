from db import db  # Import db from db.py
from flask_login import UserMixin  # Import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Add relationship to files
    files = db.relationship('File', back_populates='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Add File model here
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationship back to user
    user = db.relationship('User', back_populates='files')
    
    def __repr__(self):
        return f'<File {self.filename}>'

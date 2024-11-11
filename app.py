from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import pyotp
import os
import pytz
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from db import db  # Import db from db.py
from authguard_app.models import User  # Import User from models

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'my_secret_key'

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Set a timeout period (15 minutes for session timeout)
SESSION_TIMEOUT = timedelta(minutes=15)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anubhavezhuthassan23@gnu.ac.in'
app.config['MAIL_PASSWORD'] = 'Anubhav@Guni$013.748'
mail = Mail(app)

# File upload configurations
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 1000000

# DATABASE Configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/authguard.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'authguard.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)  # Initialize db with the app

# Import models (User, etc.)
from authguard_app.models import User

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# File model for file uploads
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='files')

User.files = db.relationship('File', back_populates='user')

# Routes

# Index page
@app.route('/')
def index():
    return render_template('index.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Fetch user from the database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)

            # Generate and send OTP
            otp_secret = pyotp.random_base32()
            otp = pyotp.TOTP(otp_secret)
            otp_code = otp.now()

            # Store OTP secret in database and session
            user.otp_secret = otp_secret
            db.session.commit()

            session['otp'] = otp_code
            session['username'] = username

            # Send OTP via Email
            msg = Message('Your OTP Code', sender='your-email@example.com', recipients=[user.email])
            msg.body = f'Your OTP code is: {otp_code}'
            mail.send(msg)

            # Set the login timestamp
            session['login_time'] = datetime.now(pytz.utc)
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if the username already exists
        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Username is already taken. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        # Check if the email already exists
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Email is already registered. Please use a different email.', 'error')
            return redirect(url_for('signup'))
        
        # If username and email are unique, create the new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)  
        db.session.add(new_user)
        db.session.commit()
        
        flash('You have successfully signed up! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# File upload route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'warning')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'warning')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Save file to database
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully', 'success')
            return redirect(url_for('dashboard'))
    return render_template('upload.html')

# OTP Verification
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form['otp']
        otp_code = session.get('otp')
        
        if otp_input == otp_code:
            # Clear OTP from session after verification
            session.pop('otp', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html')

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('dashboard.html', username=username, files=files)

# File download
@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Check session timeout on each request
@app.before_request
def check_session_timeout():
    if 'login_time' in session:
        current_time = datetime.now(pytz.utc)
        login_time = session['login_time']
        elapsed_time = current_time - login_time
        if elapsed_time > SESSION_TIMEOUT:
            session.pop('login_time', None)
            logout_user()
            flash("You have been logged out due to inactivity.", "warning")
            return redirect(url_for('login'))

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('login_time', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# Create uploads folder if not exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

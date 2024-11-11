from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import pyotp
import os
import pytz
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
# FOR DATABASE
from flask_sqlalchemy import SQLAlchemy 
from authguard import create_app, db
from authguard.models import User

app = Flask(__name__)
app.secret_key = 'my_secret_key'

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# File upload configurations
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 1000000

# Set a timeout period (15 minutes for session timeout)
SESSION_TIMEOUT = timedelta(minutes=15)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anubhavezhuthassan23@gnu.ac.in'
app.config['MAIL_PASSWORD'] = 'Anubhav@Guni$013.748'
mail = Mail(app)

# DATABASE Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User class for Flask-Login and database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(username):
    return User.query.get(username)

# Routes

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
            # Store everything OTP and username
            session['otp'] = otp_code
            session['otp_secret'] = otp_secret
            session['username'] = username

            # Send OTP via Email
            msg = Message('Your OTP Code', sender='anubhavezhuthassan23@gnu.ac.in', recipients=[user.email])
            msg.body = f'Hey buddy! You got an OTP code which is {otp_code}'
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
        new_user = User(username=username, email=email, password=hash_password(password))  # hash_password is your password hashing function
        db.session.add(new_user)
        db.session.commit()
        
        flash('You have successfully signed up! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if the user already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists, please choose another one.', 'warning')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new user and add to the database
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', back_populates='files')

User.files = db.relationship('File', back_populates='user')

# File upload route to associate files with users

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
        # Retrieve stored OTP and secret
        otp_code = session.get('otp')
        if otp_input == otp_code:
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html')

# Dashboard for file upload/download
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
        # Get the current time in UTC
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

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)

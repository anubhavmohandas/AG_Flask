from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import pyotp
import os
import pytz
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'my_secret_key'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 1000000

# Set a timeout period (5 minutes for testing)
SESSION_TIMEOUT = timedelta(minutes=15)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anubhavezhuthassan23@gnu.ac.in'
app.config['MAIL_PASSWORD'] = 'Anubhav@Guni$013.748'
mail = Mail(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory user storage (for simplicity, replace with a database later)
users = {
    'test': {
        'password': 'test',
        'email': 'anubhavezhuthassan23@gnu.ac.in'
    },
    'anubhav': {
        'password': 'anubhav',
        'email': 'anubhav.manav147@gmail.com'
    }
}


# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None

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
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)

            # Generate and send OTP
            otp_secret = pyotp.random_base32()  # Unique OTP secret for added security
            otp = pyotp.TOTP(otp_secret)
            otp_code = otp.now()
            session['otp'] = otp_code  # Store OTP
            session['otp_secret'] = otp_secret  # Store OTP secret
            session['username'] = username  # Store username

            # Send OTP via Email
            msg = Message('Your OTP Code', sender='anubhavezhuthassan23@gnu.ac.in', recipients=[users[username]['email']])
            msg.body = f'Hey buddy! You got an OTP code which is {otp_code}'
            mail.send(msg)

            # Set the login timestamp
            session['login_time'] = datetime.now(pytz.utc)
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

# File upload with error handling
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

@app.route('/signup')
def signup():
    return render_template('signup.html')

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

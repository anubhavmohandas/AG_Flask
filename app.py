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
app.config['MAX_CONTENT_LENGTH'] = 1000000  # Max file size (in bytes)

# Set a timeout period (1 minute for testing)
SESSION_TIMEOUT = timedelta(minutes=1)

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
            otp = pyotp.TOTP('base32secret3232')
            otp_code = otp.now()
            session['otp'] = otp_code  # Store OTP

            # Send OTP via Email
            msg = Message('Your OTP Code', sender='anubhavezhuthassan23@gnu.ac.in', recipients=[users[username]['email']])
            msg.body = f'Your OTP code is {otp_code}'
            mail.send(msg)

            # Set the login timestamp
            session['login_time'] = datetime.now(pytz.utc)
            # session['login_time'] = datetime.now()
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# OTP Verification
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form['otp']
        if otp_input == session.get('otp'):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP')
    return render_template('verify_otp.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

# Dashboard for file upload/download
@app.route('/dashboard')
@login_required
def dashboard():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('dashboard.html', files=files)

# File upload
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully')
            return redirect(url_for('dashboard'))
    return render_template('upload.html')

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
        current_time = datetime.now(pytz.utc)  # Use UTC
        login_time = session['login_time']  # This is naive, convert it to UTC

        # Convert login_time to UTC
        if isinstance(login_time, datetime):
            login_time = login_time.replace(tzinfo=pytz.utc)  # Make login_time UTC aware

        elapsed_time = current_time - login_time
        print(f"Elapsed time: {elapsed_time.total_seconds()} seconds")  # Debugging statement
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
    session.pop('login_time', None)  # Clear the login time from session
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)

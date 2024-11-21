from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysql import MySQL

app = Flask('__name__')
app.secret_key = 'secret_key'

# MYSQL Connection
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'

mysql = MySQL(app)

@app.route('/')
def home():
    if 'username' in sessions:
        return render_template('home.html', username=sessions['username'])
    else:
        return render_template('login.html')

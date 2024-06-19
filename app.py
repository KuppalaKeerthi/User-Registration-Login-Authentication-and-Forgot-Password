from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import secrets
import re
import time
from sqlalchemy.exc import OperationalError
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = ''
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your username'
app.config['MAIL_PASSWORD'] = 'your password'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile_number = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class ResetLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reset_link = db.Column(db.String(32), unique=True, nullable=False)
    reset_link_expiration_time = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(8), nullable=False)

with app.app_context():
    db.create_all()  # Create the tables

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        if 'email' in request.form:
            email = request.form['email']
            user = User.query.filter_by(email=email).first()

            if user:
                otp = secrets.token_hex(4)  # Generate a 4-digit OTP
                reset_link = secrets.token_hex(16)
                expiration_time = int(time.time()) + RESET_LINK_EXPIRATION_TIME
                reset = ResetLink(reset_link=reset_link, reset_link_expiration_time=expiration_time, email=email, otp=otp)
                db.session.add(reset)
                db.session.commit()

                msg = Message('Password Reset', sender='kknsdurga123@gmail.com', recipients=[email])
                msg.body = f'Please click on the following link to reset your password: http://localhost:5000/reset_password/{email}'
                mail.send(msg)

                flash('Please check your email to create a new password.', 'info')
                return redirect(url_for('check_email'))
            else:
                flash('Email not found. Please try again.', 'danger')
                return redirect(url_for('recover_password'))
        else:
            flash('Email field is required', 'danger')
            return redirect(url_for('welcome'))

    return render_template('recover_password.html')

@app.route('/check_email')
def check_email():
    return render_template('check_email.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    reset = ResetLink.query.filter_by(email=email).first()
    if reset:
        otp = reset.otp
    else:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if otp != entered_otp:
            flash('Invalid OTP. Please try again.', 'danger')
            return render_template('reset_password.html', email=email, otp=otp)
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', email=email, otp=otp)
        else:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user = User.query.filter_by(email=email).first()
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated successfully!', 'success')
            return redirect(url_for('welcome'))  # Redirect to welcome page

    return render_template('reset_password.html', email=email, otp=otp)
def display_users():
    for i in range(3):  # retry up to 3 times
        try:
            users = User.query.all()
            break
        except OperationalError as e:
            if i < 2:  # retry if it's not the last attempt
                print(f"Retrying due to OperationalError: {e}")
                time.sleep(1)  # wait for 1 second before retrying
            else:
                raise  # raise the exception if all retries fail
    return users


@app.route('/otp_verification/<email>', methods=['GET', 'POST'])
def otp_verification(email):
    if request.method == 'POST':
        otp = request.form['otp']
        reset = ResetLink.query.filter_by(email=email).first()
        if reset and reset.otp == otp:
            print("OTP verified successfully!")
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('reset_password', email=email))
    return render_template('otp_verification.html', email=email)


@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    return render_template('welcome.html')


RESET_LINK_EXPIRATION_TIME = 3600  # 1 hour

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        mobile_number = request.form['mobile_number']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, mobile_number=mobile_number, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully.', 'uccess')
        return redirect(url_for('welcome', username=username))
    return render_template('sign_up.html')
@app.route('/log_out', methods=['POST'])
def log_out():
    flash('You have been logged out.', 'uccess')
    return redirect(url_for('home'))
@app.route('/log_in', methods=['GET', 'POST'])
def log_in():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']

        user = User.query.filter((User.username == identifier) | (User.email == identifier) | (User.mobile_number == identifier)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            flash('Logged in successfully.', 'uccess')
            return redirect(url_for('welcome', username=user.username))
        else:
            flash('Login Unsuccessful. Please check your credentials', 'danger')
            return redirect(url_for('log_in'))
    return render_template('log_in.html')

@app.route('/display_users')
def display_users():
    users = User.query.all()
    return render_template('display_users.html', users=users)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('display_users'))

if __name__ == '__main__':
    app.run(debug=True)

import time
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '310364f5338c9aabd788c7b5aa1eb329ae44548b417b819b9de40d68873e6107'  # Replace with your generated secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'CRCHUM.HealthPredictor@outlook.com'
app.config['MAIL_PASSWORD'] = 'nd7E]KMXE;'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    loading = False
    token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789'

    def get_reset_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetTokenForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class SubmittingResetTokenForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('This email address is already in use. <a href="/login">Click here to login</a>', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger') #check to see if this is the reason why the error isnt showing up correctly when wrong password is entered for registered email account
            
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    input_data = request.form.to_dict()
    # Implement prediction logic here
    prediction = "Prediction logic not implemented yet"
    return render_template('index.html', prediction=prediction)

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        print("Email has been sent")
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)



# reset_token redirects the user to reset_token_submitting
@app.route('/reset_token/<token>', methods=['GET', 'POST']) 
def reset_token(token):

    form = ResetTokenForm() # Creates a ui form for the user to input new password
    if User.loading == False: # Checks if the user is loading into reset_token_submitting
        User.loading = True # If not we redirect them and set loading to True
        return redirect(url_for('reset_token',token=token)) # Redirects the user 
    return render_template('reset_token.html', form=form) # Renders the reset password page

# reset_token_submitting is where all the backend processes happen for resetting the users password 
@app.route('/reset_token_submitting', methods=['GET', 'POST']) # redirects the user into the function by link
def reset_token_submitting():
    form = SubmittingResetTokenForm() # Creates a form needed to validate the Reset button press
    user = User.query.filter_by(email=request.form.get("email")).first() # Finds the Users email to link the password
    if form.validate_on_submit(): # Checks if the button is pressed
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256') # Converts the inputted password into hash
        user.password = hashed_password # Sets the new password
        db.session.commit() # Any changes that are pending change get forced to change
        return redirect(url_for('login')) # Sends the user to login
    return render_template('reset_token_submitting.html', form=form) # Renders the submitting page



def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='CRCHUM.HealthPredictor@outlook.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:{url_for('reset_token', token=token, _external=True)}If you did not make this request then simply ignore this email and no changes will be made.'''
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request,redirect,url_for,flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'AnysercretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/aabdu/OneDrive/Desktop/User/database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField("Userame", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=80)])
    remember = BooleanField("Remember Me")



class RegisterForm(FlaskForm):
    email = StringField("E-mail", validators=[DataRequired(), Email(message='Invalid email'), Length(max=50)])
    username= StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=80)])


@app.route("/")
def index():
    return render_template('base.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash(f' {form.username.data} has been logged in successfully!')
                return redirect(url_for('dashboard'))
                flash(f' {form.username.data} has been logged in successfully!')

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + '</h1>'

    return render_template('login.html', form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash(f' Account has been created for {form.username.data} has been created sucessfully! ')
        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'


    return render_template('register.html', form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    #flash(f' {form.username.data} now has access to the dashboard page ')
    return render_template('index.html', name= current_user.username)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    #flash(f' {form.username.data} has now been logged out successfully! ')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

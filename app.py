from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, DateField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required, current_user

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    country = db.Column(db.String(30), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    role_on_a_pitch = db.Column(db.String(20), nullable=False)

    def __init__(self, name, last_name, country, date_of_birth, role_on_a_pitch):
        self.name = name
        self.last_name = last_name
        self.country = country
        self.date_of_birth = date_of_birth
        self.role_on_a_pitch = role_on_a_pitch

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email_adress = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(60), nullable=False)
    reg_date = db.Column(db.DateTime, nullable=False, default=datetime.now())
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active_now = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, username, email_adress, password, reg_date, is_admin, is_active_now):
        self.username = username
        self.email_adress = email_adress
        self.password = password
        self.reg_date = reg_date
        self.is_admin = is_admin
        self.is_active_now = is_active_now

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, password_to_login):
        return bcrypt.check_password_hash(self.password_hash, password_to_login)
    

class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a diffrent username')
        
    def validate_email_adress(self, email_adress_to_check):
        email_adress = User.query.filter_by(email_adress=email_adress_to_check.data).first()
        if email_adress:
            raise ValidationError('Email Adress already exists! Please try a diffrent email adress')

    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    email_adress = StringField(label='Email Adress:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label="Password:", validators=[DataRequired()])
    submit = SubmitField(label='Sign in')

class AddPlayerForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    last_name = StringField(validators=[DataRequired()])
    country = StringField(validators=[DataRequired()])
    date_of_birth = DateField(validators=[DataRequired()])
    role_on_a_pitch = SelectField(choices=['Goalkeeper','Defender','Midfielder', 'Striker'],validators=[DataRequired()])
    submit = SubmitField(label='Save')

class EditPlayerForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    last_name = StringField(validators=[DataRequired()])
    country = StringField(validators=[DataRequired()])
    date_of_birth = DateField(validators=[DataRequired()])
    role_on_a_pitch = SelectField(choices=['Goalkeeper','Defender','Midfielder', 'Striker'],validators=[DataRequired()])
    submit = SubmitField(label='Save changes')

@app.route('/')
def index():
    db.create_all()
    return render_template('index.html')

@app.route('/users', methods=['GET'])
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/players', methods=['GET', 'POST'])
@login_required
def players():
    players = Player.query.all()
    add_form = AddPlayerForm()   
    if add_form.validate_on_submit():
        player_to_create = Player(name = add_form.name.data,
                                last_name = add_form.last_name.data,
                                country = add_form.country.data,
                                date_of_birth = add_form.date_of_birth.data,
                                role_on_a_pitch = add_form.role_on_a_pitch.data)
        db.session.add(player_to_create)
        db.session.commit()
        flash('New Player has been added!', category='success')
        return redirect(url_for('players'))
    return render_template('players.html', players=players, add_form=add_form)

    
@app.route('/players/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    edit_form = EditPlayerForm()
    player_to_edit = Player.query.get_or_404(id)
    if request.method == 'POST':
        player_to_edit.name = edit_form.name.data
        player_to_edit.last_name = edit_form.last_name.data
        player_to_edit.country = edit_form.country.data
        player_to_edit.date_of_birth = edit_form.date_of_birth.data
        player_to_edit.role_on_a_pitch = edit_form.role_on_a_pitch.data             
        db.session.commit()
        flash('Player has been updated!', category='success')
        return redirect(url_for('players'))
    return render_template('edit_form.html', players=players, player_to_edit=player_to_edit, edit_form=edit_form)

@app.route('/players/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
      player_to_delete = Player.query.get_or_404(id)
      db.session.delete(player_to_delete)  
      db.session.commit()
      flash('Player deleted successfully!', category='info')
      return redirect(url_for('players'))
      
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              email_adress=form.email_adress.data,
                              password=form.password1.data,
                              reg_date=datetime.now(),
                              is_admin=False,
                              is_active_now=False)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f'Account created successfully! Now you are logged in as {user_to_create.username}', category="success")
        user_to_create.is_active_now=True
        db.session.commit()
        return redirect(url_for('index'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_to_login = User.query.filter_by(username=form.username.data).first()
        if user_to_login and user_to_login.check_password_correction(password_to_login=form.password.data):
            login_user(user_to_login)
            flash(f'You have been successfully logged in as: {user_to_login.username}', category='success')
            user_to_login.is_active_now=True
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash('Username and password ane not match! Please try again', category='danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    current_user.is_active_now=False
    db.session.commit()
    logout_user()
    flash('You have been logged out!', category='info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
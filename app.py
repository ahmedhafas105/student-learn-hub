from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)

# --- LOGIN MANAGER ---
@login_manager.user_loader
def load_user(user_id):
    # FIXED: Use modern db.session.get()
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You don\'t have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- FORMS ---
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update User')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user:
                raise ValidationError('That username is already taken.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=self.email.data).first()
            if user:
                raise ValidationError('That email is already registered.')
    
class CourseForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=5, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    image_url = StringField('Image URL', validators=[DataRequired()])
    submit = SubmitField('Save Course')

# --- ROUTES ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('user_home'))
    return render_template('home.html')

@app.route('/user_home')
@login_required
def user_home():
    all_courses = Course.query.all()
    return render_template('user_home.html', courses=all_courses)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            new_user = User(username=form.username.data, email=form.email.data)
            new_user.set_password(form.password.data)
            if User.query.count() == 0:
                new_user.role = 'admin'
                flash('Admin account created successfully!', 'success')
            else:
                flash('Account created successfully!', 'success')
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        flash('A user with that username already exists.', 'danger')

    return render_template('sign_up.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            if user.role == 'admin':
                flash('Welcome Admin!', 'success')
                return redirect(url_for('admin'))
            else:
                flash('Logged in successfully!', 'success')
                return redirect(url_for('user_home'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    # Added a more specific flash message
    flash('You have been successfully logged out.', 'success') 
    return redirect(url_for('home'))

# --- ADMIN ROUTES ---
@app.route('/admin')
@login_required
@admin_required
def admin():
    view = request.args.get('view', 'users')
    data = None
    if view == 'users':
        data = User.query.all()
    elif view == 'courses':
        data = Course.query.all()
    else:
        return redirect(url_for('admin', view='users'))
    
    form = EditUserForm(original_username=None, original_email=None)
    course_form = CourseForm()
    return render_template('admin_panel.html', active_view=view, data=data, form=form, course_form=course_form)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    # FIXED: Use modern db.session.get()
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash("User not found.", "danger")
        return redirect(url_for('admin', view='users'))
    if user_to_delete.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
    else:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully!", "success")
    return redirect(url_for('admin', view='users'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    # FIXED: Use modern db.session.get()
    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit:
        flash("User not found.", "danger")
        return redirect(url_for('admin', view='users'))
    form = EditUserForm(original_username=user_to_edit.username, original_email=user_to_edit.email)
    if form.validate_on_submit():
        user_to_edit.username = form.username.data
        user_to_edit.email = form.email.data
        db.session.commit()
        flash('User details updated successfully!', 'success')
        return redirect(url_for('admin', view='users'))
    elif request.method == 'GET':
        form.username.data = user_to_edit.username
        form.email.data = user_to_edit.email
    return render_template('edit_user.html', form=form, user=user_to_edit)

@app.route('/add_course', methods=['GET', 'POST'])
@login_required
@admin_required
def add_course():
    form = CourseForm()
    if form.validate_on_submit():
        new_course = Course(title=form.title.data, description=form.description.data, image_url=form.image_url.data)
        db.session.add(new_course)
        db.session.commit()
        flash('Course added successfully!', 'success')
        return redirect(url_for('admin', view='courses'))
    return render_template('course_form.html', form=form, title='Add New Course')

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_course(course_id):
    # FIXED: Use modern db.session.get()
    course = db.session.get(Course, course_id)
    if not course:
        flash("Course not found.", "danger")
        return redirect(url_for('admin', view='courses'))
    form = CourseForm()
    if form.validate_on_submit():
        course.title = form.title.data
        course.description = form.description.data
        course.image_url = form.image_url.data
        db.session.commit()
        flash('Course updated successfully!', 'success')
        return redirect(url_for('admin', view='courses'))
    elif request.method == 'GET':
        form.title.data = course.title
        form.description.data = course.description
        form.image_url.data = course.image_url
    return render_template('course_form.html', form=form, title='Edit Course')

@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
@admin_required
def delete_course(course_id):
    # FIXED: Use modern db.session.get()
    course = db.session.get(Course, course_id)
    if course:
        db.session.delete(course)
        db.session.commit()
        flash('Course deleted successfully!', 'success')
    else:
        flash("Course not found.", "danger")
    return redirect(url_for('admin', view='courses'))

# --- APP RUNNER ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
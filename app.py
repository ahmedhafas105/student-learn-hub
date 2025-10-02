import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# --- CONFIGURATION FOR FILE UPLOADS ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

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
    address = db.Column(db.String(200), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    description = db.Column(db.Text, nullable=True)
    profile_picture = db.Column(db.String(100), nullable=False, default='default.jpg') # Add default profile picture
    courses = db.relationship('Course', backref='institution', lazy=True, cascade="all, delete-orphan")
    applications = db.relationship('CourseApplication', backref='applicant', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    institution_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    applications = db.relationship('CourseApplication', backref='course', lazy=True, cascade="all, delete-orphan")

class CourseApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')

# --- LOGIN MANAGER ---
@login_manager.user_loader
def load_user(user_id):
    # Use modern db.session.get()
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You don\'t have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# NEW DECORATOR for both Admin and Institution
def panel_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'institution']:
            flash('You do not have permission to access this panel.', 'danger')
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

class InstitutionSignupForm(SignupForm):
    username = StringField('Institution Name', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Official Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    address = StringField('Address', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Register as Institution')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
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

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    address = StringField('Address')
    country = StringField('Country')
    phone_number = StringField('Phone Number')
    description = TextAreaField('Description')
    submit_profile = SubmitField('Update Profile')

# NEW: Form for changing password
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit_password = SubmitField('Change Password')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- ROUTES ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('user_home'))
    return render_template('home.html')

@app.route('/user_home')
@login_required
def user_home():
    # user_application_ids = []
    all_courses = Course.query.all()
    application_statuses = {}

    if current_user.role == 'user':
        # user_application_ids = [app.course_id for app in current_user.applications]
        for app in current_user.applications:
            application_statuses[app.course_id] = app.status
    elif current_user.role == 'institution':
        all_courses = Course.query.filter_by(institution_id=current_user.id).all()
    
    return render_template('user_home.html', courses=all_courses, application_statuses=application_statuses)

# --- COMBINED SIGNUP ROUTE ---
# In app.py

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    user_form = SignupForm()
    institution_form = InstitutionSignupForm()

    if request.method == 'POST':
        # Check which form was submitted
        if request.form.get('form_type') == 'user' and user_form.validate_on_submit():
            existing_user = User.query.filter_by(username=user_form.username.data).first()
            if existing_user is None:
                new_user = User(username=user_form.username.data, email=user_form.email.data)
                new_user.set_password(user_form.password.data)
                
                # The "first user is admin" logic remains here
                if User.query.count() == 0: new_user.role = 'admin'
                db.session.add(new_user)
                db.session.commit()
                flash('Admin account created successfully!')
                return redirect(url_for('login'))
            flash('A user with that username already exists.')
        
        elif request.form.get('form_type') == 'institution' and institution_form.validate_on_submit():
            existing_user = User.query.filter_by(username=institution_form.username.data).first()
            if existing_user is None:
                new_institution = User(
                    username=institution_form.username.data, email=institution_form.email.data, role='institution',
                    address=institution_form.address.data, country=institution_form.country.data,
                    phone_number=institution_form.phone_number.data, description=institution_form.description.data
                )
                new_institution.set_password(institution_form.password.data)
                db.session.add(new_institution)
                db.session.commit()
                flash('Institution account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            flash('An institution with that name already exists.', 'danger')

    return render_template('sign_up.html', user_form=user_form, institution_form=institution_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            if user.role in ['admin', 'institution']:
                if user.role == 'admin':
                    flash('Welcome back, Admin!', 'success')
                elif user.role == 'institution':
                    flash('Welcome back, Institution!', 'success')
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

# -- NEW USER PROFILE ROUTE ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    profile_form = ProfileForm()
    password_form = ChangePasswordForm()

    if profile_form.submit_profile.data and profile_form.validate_on_submit():
        current_user.username = profile_form.username.data
        current_user.email = profile_form.email.data
        if current_user.role == 'institution':
            current_user.address = profile_form.address.data
            current_user.country = profile_form.country.data
            current_user.phone_number = profile_form.phone_number.data
            current_user.description = profile_form.description.data

        # Handle file upload
        if profile_form.picture.data and allowed_file(profile_form.picture.data.filename):
            picture_file = secure_filename(profile_form.picture.data.filename)
            picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_file)
            profile_form.picture.data.save(picture_path)
            current_user.profile_picture = picture_file

        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    
    if password_form.submit_password.data and password_form.validate_on_submit():
        # Handle password change
        if current_user.check_password(password_form.current_password.data):
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            flash('Your password has been changed successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Current password is incorrect.', 'danger')

    # Pre-populate form with existing data on GET request
    profile_form.username.data = current_user.username
    profile_form.email.data = current_user.email
    if current_user.role == 'institution':
        profile_form.address.data = current_user.address
        profile_form.country.data = current_user.country
        profile_form.phone_number.data = current_user.phone_number
        profile_form.description.data = current_user.description

     # Fetch data for display based on role
    pending_applications, enrolled_courses, approved_applications = [], [], []

    if current_user.role == 'user':
        # Fetch user application data
        applications = CourseApplication.query.filter_by(user_id=current_user.id).all()
        pending_applications = [app for app in applications if app.status == 'Pending']
        enrolled_courses = [app for app in applications if app.status == 'Approved']
    elif current_user.role == 'institution':
        # ... (fetch institution approved application data)
        approved_applications = db.session.query(CourseApplication).join(Course).filter(
            Course.institution_id == current_user.id,
            CourseApplication.status == 'Approved'
        ).all()

    return render_template(
        'profile.html', 
        profile_form=profile_form,
        password_form=password_form,
        pending_applications=pending_applications,
        enrolled_courses=enrolled_courses,
        approved_applications=approved_applications
    )

# --- NEW: COURSE APPLICATION ROUTE ---
@app.route('/apply/<int:course_id>', methods=['POST'])
@login_required
def apply_course(course_id):
    if current_user.role != 'user':
        flash('Only users can apply for courses.', 'danger')
        return redirect(url_for('user_home'))

    # Check if user has already applied
    existing_application = CourseApplication.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if existing_application:
        flash('You have already applied for this course.', 'warning')
    else:
        new_application = CourseApplication(user_id=current_user.id, course_id=course_id)
        db.session.add(new_application)
        db.session.commit()
        flash('You have successfully applied for the course!', 'success')
    return redirect(url_for('user_home'))

# --- ADMIN ROUTES ---
@app.route('/admin')
@login_required
@panel_required
def admin():
    # Authorization check
    if current_user.role not in ['admin', 'institution']:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user_home'))
    
    view = request.args.get('view', 'courses' if current_user.role == 'institution' else 'users')
    data = None

    # Prevent institution from accessing user management
    if current_user.role == 'institution' and view == 'users':
        return redirect(url_for('admin', view='courses'))
    
    if view == 'users':
        data = User.query.all()
    elif view == 'courses':
        if current_user.role == 'admin':
            data = Course.query.all()
        else: # It's an institution
            data = Course.query.filter_by(institution_id=current_user.id).all()
    elif view == 'applications':
        if current_user.role == 'institution':
            # Join Application with Course to filter by institution
            data = db.session.query(CourseApplication).join(Course).filter(Course.institution_id == current_user.id).all()
        else: # Admin shouldn't see this view
            return redirect(url_for('admin', view='users'))
    else:
        return redirect(url_for('admin', view='users'))
    
    form = EditUserForm(original_username=None, original_email=None)
    course_form = CourseForm()
    return render_template('admin_panel.html', active_view=view, data=data, form=form, course_form=course_form)

# NEW: APPLICATION HANDLING ROUTE
@app.route('/handle_application/<int:application_id>/<action>', methods=['POST'])
@login_required
@panel_required
def handle_application(application_id, action):
    if current_user.role != 'institution':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))
    
    application = db.session.get(CourseApplication, application_id)
    if not application or application.course.institution_id != current_user.id:
        flash('Application not found or you don\'t have permission to access it.', 'danger')
        return redirect(url_for('admin', view='applications'))
    
    if action == 'approve': application.status = 'Approved'
        # flash('Application approved.', 'success')
    elif action == 'reject': application.status = 'Rejected'
        # flash('Application rejected.', 'warning')
    

    db.session.commit()
    flash(f'Application {application.status.lower()}.', 'success')
    return redirect(url_for('admin', view='applications'))

# --- ADMIN USER MANAGEMENT ROUTES ---

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    # Used modern db.session.get()
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
    # Used modern db.session.get()
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
@panel_required
def add_course():
    if current_user.role not in ['admin', 'institution']:
        flash('You do not have permission.', 'danger')
        return redirect(url_for('user_home'))
    form = CourseForm()
    if form.validate_on_submit():
        new_course = Course(title=form.title.data, description=form.description.data, image_url=form.image_url.data, institution_id=current_user.id)
        db.session.add(new_course)
        db.session.commit()
        flash('Course added successfully!', 'success')
        return redirect(url_for('admin', view='courses'))
    return render_template('course_form.html', form=form, title='Add New Course')

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
@panel_required
def edit_course(course_id):
    # Used modern db.session.get()
    course = db.session.get(Course, course_id)
    if not course or (current_user.role == 'institution' and course.institution_id != current_user.id):
        flash("Course not found or You don't have permission.", "danger")
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
@panel_required
def delete_course(course_id):
    # Used modern db.session.get()
    course = db.session.get(Course, course_id)
    if not course or (current_user.role == 'institution' and course.institution_id != current_user.id):
        flash("Course not found or You don't have permission.", "danger")
    else:
        db.session.delete(course)
        db.session.commit()
        flash('Course deleted successfully!', 'success')
    return redirect(url_for('admin', view='courses'))

# --- APP RUNNER ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
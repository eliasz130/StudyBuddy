from flask import Flask, render_template, redirect, url_for, request, flash # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from sqlalchemy.exc import SQLAlchemyError # type: ignore
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# SQLite Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'studybuddy.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# DB Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    
    tasks = db.relationship('Tasks', backref='user', lazy=True)
    study_sessions = db.relationship('StudySession', backref='user', lazy=True)
    progress_records = db.relationship('Progress', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(120), nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    priority = db.Column(db.Integer, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    @property
    def duration(self):
        return int((self.end_time - self.start_time).total_seconds() / 60)  # in minutes
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    progress_percentage = db.Column(db.Integer, nullable=False, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.context_processor
def inject_user():
    return {'user': current_user}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():  # sourcery skip: use-named-expression
    if request.method != 'POST':
        return render_template('register.html')

    username = request.form['username']
    import re
    email = request.form['email']
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        flash('Invalid email address', 'danger')
        return redirect(url_for('register'))
    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        flash('Email already exists', 'danger')
        return redirect(url_for('register'))
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('register'))
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists', 'danger')
        return redirect(url_for('register'))

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/task/<int:task_id>')
@login_required
def task(task_id):
    task = Tasks.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('task_detail.html', task=task)

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    render_template('create_task.html')
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    
    if not name or not description:
        flash('Task name and description are required', 'danger')
        return redirect(url_for('dashboard'))
    
    if len(name) > 80 or len(description) > 120:
        flash('Task name or description too long', 'danger')
        return redirect(url_for('dashboard'))
    
    new_task = Tasks(name=name, description=description, user_id=current_user.id)
    
    try:
        db.session.add(new_task)
        db.session.commit()
        flash('Task created successfully', 'success')
    except SQLAlchemyError:
        db.session.rollback()
        flash('Error creating task', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/tasks.html', methods=['GET'])
def view_tasks():
    tasks = Tasks.query.filter_by(user_id=current_user.id).all()
    if not tasks:
        flash('No tasks found', 'info')
        return redirect(url_for('dashboard'))
    return render_template('tasks.html', tasks=tasks)

if __name__ == '__main__':
    db.create_all()
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)
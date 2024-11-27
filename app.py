# Imports
from datetime import datetime, timezone
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from sqlalchemy.exc import SQLAlchemyError # type: ignore
from sqlalchemy import or_ # type: ignore
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
import os
import re
from enum import Enum
from flask_migrate import Migrate # type: ignore
from distutils.util import strtobool # type: ignore

# Flask Configuration
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# SQLite Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'studybuddy.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask DB
db = SQLAlchemy()
db.init_app(app)

# Initialize Flask Migrate
migrate = Migrate(app, db)

# Initialize Flask Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Enums
class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

class TaskStatus(Enum):
    NOT_STARTED = 1
    IN_PROGRESS = 2
    COMPLETED = 3

# DB Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')
    study_sessions = db.relationship('StudySession', backref='user', lazy=True)
    progress_records = db.relationship('Progress', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_last_login(self):
        self.last_login = datetime.now(timezone.utc)
        db.session.commit()

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    priority = db.Column(db.Enum(TaskPriority), default=TaskPriority.MEDIUM)
    status = db.Column(db.Enum(TaskStatus), default=TaskStatus.NOT_STARTED)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_url = db.Column(db.String(255))
    tags = db.Column(db.String(200))  # Comma-separated tags
    
    study_sessions = db.relationship('StudySession', backref='task', lazy=True)
    progress = db.relationship('Progress', backref='task', lazy=True)

    @property
    def is_overdue(self):
        return self.due_date and self.due_date < datetime.now(timezone.utc)

    @property
    def total_study_time(self):
        return sum(session.duration for session in self.study_sessions)

    def update_status(self, new_status):
        self.status = new_status
        db.session.commit()

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @property
    def duration(self):
        if self.end_time:
            return int((self.end_time - self.start_time).total_seconds() / 60)
        return 0

    def end_session(self, notes=None):
        self.end_time = datetime.now(timezone.utc)
        if notes:
            self.notes = notes
        db.session.commit()

class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    progress_percentage = db.Column(db.Integer, nullable=False, default=0)
    notes = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')

# Login and Registration
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.update_last_login()
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

    try:
        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('An error occurred during registration. Please try again.', 'danger')
        return redirect(url_for('register'))

# Profile, Logout, and Dashboard
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

# Tasks
@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        try:
            new_task = Task(
                title=request.form['title'].strip(),
                description=request.form['description'].strip(),
                due_date=datetime.strptime(request.form['due_date'], '%Y-%m-%d') if request.form.get('due_date') else None,
                priority=TaskPriority[request.form['priority'].upper()],
                user_id=current_user.id,
                image_url=request.form.get('image_url'),
                tags=request.form.get('tags', '').strip()
            )
            
            db.session.add(new_task)
            db.session.commit()
            
            flash('Task created successfully!', 'success')
            return redirect(url_for('view_tasks'))
            
        except (ValueError, KeyError) as e:
            flash(f'Invalid input: {str(e)}', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash('Database error occurred', 'danger')
            
    return render_template('create_task.html', priorities=TaskPriority)

@app.route('/task/<int:task_id>/start_session', methods=['POST'])
@login_required
def start_study_session(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    session = StudySession(
        start_time=datetime.now(timezone.utc),
        task_id=task_id,
        user_id=current_user.id,
    )
    db.session.add(session)
    db.session.commit()

    return jsonify({
        'session_id': session.id,
        'start_time': session.start_time.isoformat()
    })

@app.route('/task/<int:task_id>/update_progress', methods=['POST'])
@login_required
def update_progress(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    progress_percentage = request.form.get('progress', type=int)
    if progress_percentage is None or not (0 <= progress_percentage <= 100):
        return jsonify({'error': 'Progress percentage must be between 0 and 100'}), 400

    progress = Progress(
        task_id=task_id,
        progress_percentage=progress_percentage,
        notes=request.form.get('notes'),
        user_id=current_user.id
    )

    db.session.add(progress)
    db.session.commit()

    return jsonify({
        'progress_id': progress.id,
        'progress_percentage': progress.progress_percentage
    })

@app.route('/tasks')
@login_required
def view_tasks():
    sort_by = request.args.get('sort', 'due_date')
    filter_priority = request.args.get('priority')
    filter_status = request.args.get('status')
    search_query = request.args.get('q')

    query = Task.query.filter_by(user_id=current_user.id)

    if filter_priority:
        query = query.filter_by(priority=TaskPriority[filter_priority.upper()])
    if filter_status:
        query = query.filter_by(status=TaskStatus[filter_status.upper()])
    if search_query:
        query = query.filter(
            db.or_(
                or_(
                    Task.title.ilike(f'%{search_query}%'),
                    Task.description.ilike(f'%{search_query}%'),
                    Task.tags.ilike(f'%{search_query}%')
                )
            )
        )

    if sort_by == 'due_date':
        query = query.order_by(Task.due_date.asc())
    elif sort_by == 'priority':
        query = query.order_by(Task.priority.desc())
    elif sort_by == 'created':
        query = query.order_by(Task.created_at.desc())

    tasks = query.all()
    return render_template('tasks.html', tasks=tasks)

# Run app
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    debug_mode = strtobool(os.environ.get('FLASK_DEBUG', 'False'))
    app.run(debug=debug_mode)
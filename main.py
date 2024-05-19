from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///taskhub.db'
app.config['SECRET_KEY'] = 'GGEZ'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'staff_login'

ROLES = ['admin', 'staff']

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')
    is_leader = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    deadline = db.Column(db.DateTime)
    priority = db.Column(db.Integer)
    status = db.Column(db.String(20), default='Pending')
    progress = db.Column(db.Integer, default=0)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assignee = db.relationship('User', backref=db.backref('tasks', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='admin').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_index'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('admin_login.html')

@app.route('/staff_login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='staff').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('staff_login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('landing'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('landing'))
    return render_template('register.html')

@app.route('/staff_register', methods=['GET', 'POST'])
def staff_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('staff_register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, password=hashed_password, role='staff')
        db.session.add(user)
        db.session.commit()
        flash('Staff account created successfully!', 'success')
        return redirect(url_for('staff_login'))

    return render_template('staff_register.html')

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        deadline_str = request.form['deadline']  # Get deadline as string
        deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')  # Convert string to datetime object
        priority = request.form['priority']
        assignee_id = request.form['assignee_id']
        task = Task(title=title, description=description, deadline=deadline, priority=priority, assignee_id=assignee_id)
        db.session.add(task)
        db.session.commit()
        flash('Task created successfully!', 'success')
        return redirect(url_for('admin_index'))
    users = User.query.all()
    return render_template('create_task.html', users=users)

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task:
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
    return redirect(url_for('admin_index'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Permission denied. You are not authorized to perform this action.', 'error')
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_index'))

@app.route('/admin_index')
@login_required
def admin_index():
    if current_user.role != 'admin':
        flash('Permission denied. You are not authorized to view this page.', 'error')
        return redirect(url_for('index'))
    tasks = Task.query.all()
    users = User.query.all()
    return render_template('admin_index.html', tasks=tasks, users=users)

@app.route('/index')
@login_required
def index():
    tasks = Task.query.filter_by(assignee_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/update_task_progress/<int:task_id>', methods=['POST'])
@login_required
def update_task_progress(task_id):
    task = Task.query.get(task_id)
    if task and task.assignee_id == current_user.id:
        new_progress = request.form['progress']
        try:
            new_progress = int(new_progress)
            if 0 <= new_progress <= 100:
                task.progress = new_progress
                # Dynamically update the status based on progress
                if new_progress == 100:
                    task.status = 'Done'
                else:
                    task.status = f'Working ({new_progress}%)'
                db.session.commit()
                flash('Task progress updated successfully!', 'success')
            else:
                flash('Progress must be between 0 and 100.', 'error')
        except ValueError:
            flash('Progress must be an integer.', 'error')
    else:
        flash('Task not found or you are not the assignee.', 'error')
    return redirect(url_for('index'))



@app.route('/mark_task_done/<int:task_id>', methods=['POST'])
@login_required
def mark_task_done(task_id):
    task = Task.query.get(task_id)
    if task:
        task.status = 'Done'
        db.session.commit()
        flash('Task marked as done!', 'success')
    return redirect(url_for('admin_index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

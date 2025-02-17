from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Use SQLite for now
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Change this in production

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # The name of the login route

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Hashed Password

# Create Database Tables
with app.app_context():
    db.create_all()

# Load User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# App Routing Section

@app.route("/", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch user from DB
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists, please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Store new user in DB
        new_user = User(full_name=full_name, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", current_user=current_user)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Check if new password and confirm password match
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match!", 'danger')
        else:
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Update the user's password
            current_user.password = hashed_password
            db.session.commit()

            flash("Password updated successfully!", 'success')

        return redirect(url_for('profile'))

    return render_template("profile.html")


# Run the app
if __name__ == '__main__':
    app.run(debug=True)

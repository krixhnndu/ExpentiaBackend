from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_cors import CORS
from flask_migrate import Migrate  # Import Flask-Migrate
from dotenv import load_dotenv
import os

load_dotenv()
# Initialize Flask App
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)  # Enable CORS for frontend communication

# Configuration
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "your_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Secure with environment variable
app.config['MAIL_DEFAULT_SENDER'] = 'expentiaadmiapp@gmail.com'
app.config['MAIL_DEBUG'] = True

# Initialize Extensions
mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)  # Initialize Flask-Migrate

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Contact Us Route - Handles Form Submission
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not name or not email or not message:
            flash("❌ All fields are required!", "danger")
            return redirect(url_for('contact'))

        try:
            msg = Message(
                subject=f"New Contact Form Submission from {name}",
                sender=os.getenv("MAIL_USERNAME"),
                recipients=[os.getenv("MAIL_USERNAME")],  # Send to your own email
                body=f"Name: {name}\nEmail: {email}\nMessage: {message}"
            )
            mail.send(msg)

            flash("✅ Your message has been sent successfully!", "success")
            return redirect(url_for('contact'))
        except Exception as e:
            flash("❌ Error sending message. Please try again.", "danger")
            print("Email Error:", e)

    return render_template('contact.html')


# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("")
            return redirect(url_for('home'))
        else:
            flash("❌ Invalid username or password", "danger")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash("❌ Username already exists. Please choose another.", "danger")
            return redirect(url_for('signup'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash("✅ Account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# Page Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/expensetracker')
@login_required
def expensetracker():
    return render_template('expensetracker.html', username=current_user.username)

@app.route('/transactions')
@login_required
def transactions():
    return render_template('transactions.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("ℹ️ You have been logged out.", "info")
    return redirect(url_for('index'))


@app.route('/api/username')
def get_username():
    if not current_user.is_authenticated:
        return {"error": "User not logged in"}, 401  # Return 401 instead of 404

    return {"username": current_user.username}, 200

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

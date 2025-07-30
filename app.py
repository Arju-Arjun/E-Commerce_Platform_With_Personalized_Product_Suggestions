from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta, timezone
import os
import uuid
import pandas as pd
from random import randint, choice
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import sqlite3
import re
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'arjun#*12')
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['PRODUCT_UPLOAD_FOLDER'] = 'static/product_images'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB limit
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PRODUCT_UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(18), nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    location = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(20), nullable=False)
    image = db.Column(db.String(100), default='default.jpg')
    last_view = db.Column(db.Integer)
    is_verified = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, default=None)
    units_sold = db.Column(db.Integer, default=0)
    clicks = db.Column(db.Integer, default=0)
    impressions = db.Column(db.Integer, default=0)
    category = db.Column(db.String(100), default='uncategorized')
    description = db.Column(db.Text, default='No description available')
    stock = db.Column(db.String(100), default='available')
    image = db.Column(db.String(200), default='default.png')
    sub_category = db.Column(db.String(200), default='No sub category')
    conversion_rate = db.Column(db.Float, default=0.0)
    rating = db.Column(db.Float, default=1.0)
    total_rating = db.Column(db.Integer, default=0)
    rating_count = db.Column(db.Integer, default=0)
    offer = db.Column(db.Float, default=0.0)
    discounted_price = db.Column(db.Float, default=0.0)
    brand = db.Column(db.String(100), default="unknown")

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))

class Order(db.Model):
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    delivery_details = db.Column(db.String(250), nullable=False)
    order_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    delivery_date = db.Column(db.DateTime, nullable=True)
    amount = db.Column(db.Float, nullable=True, default=0.0)
    delivery_charge = db.Column(db.Float, nullable=True, default=30.0)
    img = db.Column(db.String(200), default='default.png')
    payment_method = db.Column(db.String(50), nullable=True, default='Cash on Delivery')
    quantities = db.Column(db.Float, nullable=True, default=1)
    status = db.Column(db.String(50), nullable=True, default='Processing')
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    product = db.relationship('Product', backref=db.backref('orders', lazy=True))

class UserInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    clicks = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('interactions', lazy=True))
    product = db.relationship('Product', backref=db.backref('interactions', lazy=True))

class ProductRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    order_id = db.Column(db.String, db.ForeignKey('order.id'), nullable=False)
    rating_value = db.Column(db.Integer, nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    message = db.Column(db.String(200))
    date = db.Column(db.Date, default=lambda: datetime.utcnow().date())
    respond_message = db.Column(db.String, default="")

# Helper Functions
def product():
    if os.path.exists('instance/product.csv'):
        os.remove('instance/product.csv')
    conn = sqlite3.connect('instance/db.sqlite')
    query = "SELECT * FROM product"
    df = pd.read_sql_query(query, conn)
    df.to_csv('instance/product.csv', index=False)

def preprocess_csv():
    product()
    df = pd.read_csv("instance/product.csv")
    df['product_id'] = df['id'].astype(int)
    df['description'] = df['description'].fillna('No description available')
    df['category'] = df['category'].fillna('uncategorized')
    df['name'] = df['name'].fillna('No name available')
    df['brand'] = df['brand']

    def clean_text(text):
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        return re.sub(r'\s+', ' ', text).strip().lower()

    df['combined_features'] = (
        df['sub_category'].astype(str) + ' ' +
        df['brand'].astype(str) + ' ' +
        df['name'].astype(str) + ' ' +
        df['description'].astype(str)
    ).apply(clean_text)

    tfidf = TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_df=0.85,
        min_df=2
    )
    tfidf_matrix = tfidf.fit_transform(df['combined_features'])
    content_sim = cosine_similarity(tfidf_matrix, tfidf_matrix)
    return df, content_sim

def content_based_recommendations(product_id, content_sim, df, n_products=5):
    matches = df[df['product_id'] == product_id]
    if matches.empty:
        print(f"No match found for product_id={product_id}")
        return []

    idx = matches.index[0]
    sim_scores = list(enumerate(content_sim[idx]))
    sim_scores = [(i, score) for i, score in sim_scores if score >= 0.13]
    sim_scores = sorted(sim_scores, key=lambda x: x[1], reverse=True)

    recommendations = []
    for i, score in sim_scores:
        pid = int(df.iloc[i]['product_id'])
        recommendations.append({'product_id': pid, 'similarity': score})
    return recommendations

def collaborating_based_recommendations(user_id, n_products):
    data = UserInteraction.query.with_entities(
        UserInteraction.user_id,
        UserInteraction.product_id,
        UserInteraction.clicks).all()
    df = pd.DataFrame(data, columns=['user_id', 'product_id', 'clicks'])
    if df.empty or user_id not in df['user_id'].unique():
        return []

    interaction_matrix = df.pivot_table(index='user_id', columns='product_id', values='clicks', fill_value=0)
    user_similarity = cosine_similarity(interaction_matrix)
    similarity_df = pd.DataFrame(user_similarity, index=interaction_matrix.index, columns=interaction_matrix.index)
    similar_users = similarity_df[user_id][similarity_df[user_id] > 0.3].sort_values(ascending=False)[1:]

    scores = {}
    for other_user_id, sim_score in similar_users.items():
        other_clicks = interaction_matrix.loc[other_user_id]
        for product_id, click_value in other_clicks.items():
            if interaction_matrix.loc[user_id, product_id] == 0:
                scores[product_id] = scores.get(product_id, 0) + sim_score * click_value

    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    recommended_ids = [pid for pid, _ in sorted_scores[:n_products]]
    return recommended_ids

def hybrid_based_recommendations(product_id, content_sim, df, n_products):
    content = content_based_recommendations(product_id, content_sim, df, n_products)
    collab = collaborating_based_recommendations(current_user.id, n_products=int(n_products))

    content_ids = [item['product_id'] for item in content]
    hybrid_ids = []
    seen = set()
    for pid in collab[:5] + content_ids[:5]:
        if pid not in seen:
            hybrid_ids.append(pid)
            seen.add(pid)
    return hybrid_ids[:10]

def update_order_status():
    now = datetime.now()
    orders = Order.query.all()
    for order in orders:
        if not order.delivery_date:
            continue
        delivery_dt = order.delivery_date
        if order.status == 'Processing' and now >= delivery_dt - timedelta(days=2):
            order.status = 'Dispatched'
        elif order.status == 'Dispatched' and now >= delivery_dt:
            order.status = 'Delivered'
    db.session.commit()

def get_admin():
    return Admin.query.first()

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("You need to log in as admin to access this page.", "error")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def company_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'company_logged_in' not in session:
            flash("You need to log in as admin to access this page.", "error")
            return redirect(url_for('company_login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_verification_token(email):
    return s.dumps(email, salt='email-verification')

def verify_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='email-verification', max_age=expiration)
        return email
    except (SignatureExpired, BadSignature):
        return None

# Routes
@app.route('/company_register', methods=['GET', 'POST'])
def company_register():
    if request.method == 'POST':
        name = request.form['company_name'].capitalize()
        email = request.form['email']
        password = request.form['password']
        if not name or not email:
            flash("Name and email are required.", "error")
            return redirect(url_for('company_register'))
        
        existing_company = Company.query.filter_by(email=email).first()
        if existing_company:
            flash("Company with this email already exists.", "error")
            return redirect(url_for('company_register'))

        new_company = Company(name=name, email=email, password=generate_password_hash(password))
        db.session.add(new_company)
        db.session.commit()
        flash("Company registered successfully.", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_dashboard.html')

@app.route('/company/login', methods=['GET', 'POST'])
def company_login():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        company = Company.query.filter((Company.email == username)).first()
        if company and check_password_hash(company.password, password):
            session['company_id'] = company.id
            session['company_logged_in'] = True
            return redirect(url_for('company_dashboard'))
        return redirect(url_for('company_login'))
    return render_template('company_login.html')

@app.route('/company/dashboard', methods=['GET', 'POST'])
@company_login_required
def company_dashboard():
    session['account_type'] = 'company'
    company_id = session.get('company_id')
    if not company_id:
        return redirect(url_for('company_login'))
    
    company = Company.query.get(company_id)
    name = company.name
    products = Product.query.filter_by(brand=name)
    return render_template('company_dashboard.html', products=products, name=name)

@app.route('/company/logout')
@company_login_required
def company_logout():
    session.pop('company_logged_in', None)
    return redirect(url_for('company_login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = get_admin()
        if username == admin.username and check_password_hash(admin.password, password):
            session['admin_logged_in'] = True
            flash("Admin logged in successfully.", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials.", "error")
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@admin_login_required
def admin_dashboard():
    session['account_type'] = 'admin'
    brand = db.session.query(Company.name).distinct().all()
    brand = [item[0] for item in brand]
    mail = db.session.query(Contact).order_by(Contact.id.desc()).all()
    category = db.session.query(Product.category).distinct().all()
    category_list = [item[0] for item in category]
    
    if request.method == 'POST':
        name = request.form['name']
        if not name:
            flash("Product name is required.", "error")
            return redirect(url_for('admin_dashboard'))
       
        category = request.form.get('category')
        sub_category = request.form.get('sub_category')
        price = request.form.get('price')
        offer = request.form.get('offer')
        discount = (float(offer) / 100) * float(price)
        discounted_price = round(float(price) - discount, 2)
        description = request.form.get('description')
        image_file = request.files.get('image')
        image_filename = None
        if image_file and image_file.filename != '':
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            image_filename = secure_filename(image_file.filename)
            if '.' in image_filename and image_filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                image_file.save(os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], image_filename))
            else:
                flash("Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.", "error")
                return redirect(url_for('admin_dashboard'))

        brand = request.form.get("brand")
        new_product = Product(
            name=name,
            category=category,
            sub_category=sub_category,
            price=price,
            offer=offer,
            discounted_price=discounted_price,
            description=description,
            image=image_filename,
            brand=brand,
            stock=request.form.get('yes')
        )
        db.session.add(new_product)
        db.session.commit()
        session['account_type'] = request.form.get('company', 'admin')
        flash("Product added successfully.", "success")

        if session.get('account_type') == 'company':
            return redirect(url_for('company_dashboard'))
        else:
            return redirect(url_for('admin_dashboard'))

    products = Product.query.order_by(Product.clicks.desc()).all()
    return render_template('admin_dashboard.html', products=products, brand=brand, mail=mail, category_list=category_list)

@app.route('/delete_product/<int:product_id>', methods=['POST', 'GET'])
def delete_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        UserInteraction.query.filter_by(product_id=product.id).delete()
        db.session.delete(product)
        db.session.commit()
        flash("Product and related interactions deleted.", "success")
    except Exception as e:
        print('\n\n\n\n Error:', str(e))
        flash("Error deleting product.", "danger")
    
    if session.get('account_type') == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('company_dashboard'))

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    account_type = session.get('account_type')
    brand = db.session.query(Company.name).distinct().all()
    brand = [item[0] for item in brand]
    product = Product.query.get_or_404(product_id)
    category = db.session.query(Product.category).distinct().all()
    category = [item[0] for item in category]

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form.get('description')
        product.category = request.form.get('category')
        product.sub_category = request.form.get('sub_category')
        price = product.price = request.form.get('price')
        offer = product.offer = request.form.get('offer')
        product.stock = request.form.get('stock')
        discount = (float(offer) / 100) * float(price)
        product.discounted_price = round(float(price) - discount, 2)
        product.brand = request.form.get("brand").capitalize()

        image_file = request.files.get('image')
        if image_file and image_file.filename != '':
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            image_filename = secure_filename(image_file.filename)
            if '.' in image_filename and image_filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                os.makedirs(app.config['PRODUCT_UPLOAD_FOLDER'], exist_ok=True)
                image_file.save(os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], image_filename))
                product.image = image_filename
            else:
                flash("Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.", "error")
                return redirect(url_for('edit_product', product_id=product.id))
        db.session.commit()
        flash("Product updated successfully.", "success")
        if session.get('account_type') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('company_dashboard'))
    return render_template('edit_product.html', product=product, brand=brand, account_type=account_type, category=category)

@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    categories = db.session.query(Product.category).distinct().all()
    grouped_products = []
    for (category,) in categories:
        query = Product.query.filter_by(category=category).order_by(Product.clicks.desc())
        products = query.limit(9).all()
        grouped_products.append({
            'title': category.title() if category else 'Uncategorized',
            'products': products
        })
    return render_template('index.html', grouped_products=grouped_products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email')
        if email:
            if User.query.filter_by(email=email).first():
                flash("Email already exists. Please choose a different one.", "error")
                return redirect(url_for('register'))
        phone = request.form['phone']
        if not phone.isdigit() or len(phone) != 10:
            flash("Invalid phone number. It must be 10 digits long.", "error")
            return redirect(url_for('register'))
        if User.query.filter_by(phone=phone).first():
            flash("Phone number already exists. Please choose a different one.", "error")
            return redirect(url_for('register'))
        
        location = request.form['location']
        password = request.form['password']

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)

        new_user = User(name=name, phone=phone, password=hashed_password, email=email, location=location, is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        if email:
            token = generate_verification_token(email)
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('Verify Your Email', recipients=[email])
            msg.body = f'Please click the following link to verify your email: {verify_url}'
            mail.send(msg)
            flash("Registration successful! Please check your email to verify your account.", "success")
        else:
            flash("Registration successful! Please log in.", "success")
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    email = verify_token(token)
    if not email:
        flash("The verification link is invalid or has expired.", "error")
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No user found with this email.", "error")
        return redirect(url_for('register'))

    if user.is_verified:
        flash("Email already verified.", "info")
        return redirect(url_for('login'))

    user.is_verified = True
    db.session.commit()
    flash("Email verified successfully! You can now log in.", "success")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter(
            (User.phone == username) | (User.email == username)
        ).first()

        if user and check_password_hash(user.password, password):
            if user.email and not user.is_verified:
                flash("Please verify your email before logging in.", "error")
                return redirect(url_for('login'))
            login_user(user)
            next_page = request.args.get('next')
            try:
                session.pop('last_viewed_product_id', None)
                session.pop('second_last_view', None)
            except Exception as e:
                flash(str(e), 'error')
            return redirect(next_page or url_for('dashboard'))

        flash("Invalid username or password.", "error")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('profile'))

    file = request.files['profile_pic']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('profile'))

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        current_user.image = filename
        db.session.commit()
        flash('Profile picture updated!', 'success')
    else:
        flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'error')
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user_id=current_user.id, name=current_user.name, email=current_user.email, phone=current_user.phone, location=current_user.location, image=current_user.image)

@app.route('/edit_address', methods=['GET', 'POST'])
@login_required
def edit_address():
    if request.method == 'POST':
        name = request.form.get('name').title()
        house_name = request.form.get('house_name').title()
        if house_name.endswith('(Ho)'):
            house_name = house_name
        else:
            house_name = house_name + ' (Ho)'

        house_no = request.form.get('house_no')
        street = request.form.get('street').title()
        city = request.form.get('city').title()
        post_office = request.form.get('post_office').title()

        if post_office.endswith('(Po)'):
            post_office = post_office
        else:
            post_office = post_office + ' (Po)'

        district = request.form.get('district').title()
        state = request.form.get('state').title()
        pincode = request.form.get('pincode')

        address = f"{house_name}, {house_no}, {street}, {city}, {post_office}, {district}, {state}, {pincode}\n"

        current_user.location = address
        current_user.name = name
        db.session.commit()
        flash("Address updated successfully!", "success")
        return redirect(request.args.get('next') or url_for('dashboard'))

    return render_template('edit_address.html', current_user=current_user)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        name = request.form.get('name') or current_user.name
        email = request.form.get('email') or current_user.email
        message = request.form.get('message', '')
        date = datetime.now()

        new_msg = Contact(name=name, email=email, message=message, date=date)
        db.session.add(new_msg)
        db.session.commit()
        flash('Message submitted successfully!', 'success')
        return redirect(url_for('mail'))

    return render_template('contact.html', name=current_user.name, email=current_user.email)

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    msg = Contact.query.get_or_404(message_id)
    db.session.delete(msg)
    db.session.commit()
    flash("Message deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/respond_message/<int:message_id>', methods=['GET', 'POST'])
def respond_message(message_id):
    message = Contact.query.get_or_404(message_id)
    all_messages = Contact.query.filter_by(email=message.email).order_by(Contact.id.asc()).all()

    if request.method == 'POST':
        response_text = request.form.get('response')
        if response_text:
            message.respond_message = response_text
            message.respond_date = datetime.now()
            db.session.commit()
            flash("Response sent successfully.", "success")
            return redirect(url_for('respond_message', message_id=message.id))
        else:
            flash("Response cannot be empty.", "warning")
    return render_template('respond.html', user=message, messages=all_messages, last_msg_id=message.id)

@app.route('/mail')
@login_required
def mail():
    messages = Contact.query.filter_by(email=current_user.email).order_by(Contact.date).all()
    return render_template('mail.html', messages=messages)

@app.route('/dashboard')
def dashboard():
    category = request.args.get('category', 'all')
    product_slideshow = Product.query.order_by(Product.clicks.desc()).limit(5).all()

    if category != 'all':
        products = Product.query.filter_by(category=category).order_by(Product.clicks.desc()).all()
        return render_template('dashboard.html', hybrid_products=products, product_slideshow=product_slideshow, choice=choice)
    else:
        if not current_user.is_authenticated:
            previous = []
            top_recommendations = []
            all_products = Product.query.order_by(Product.clicks.desc()).all()
            product_dict = {product.id: product for product in all_products}

            if session.get('last_viewed_product_id'):
                product_id = int(session.get('last_viewed_product_id'))
                df, content_sim = preprocess_csv()
                n_products = len(product_dict)
                raw_recommendations = content_based_recommendations(product_id, content_sim, df, n_products)
                recommended_ids = [item['product_id'] for item in raw_recommendations]
                top_recommendations = [product_dict[pid] for pid in recommended_ids if pid in product_dict][:6]

                if session.get('second_last_view'):
                    product_id = int(session.get('second_last_view'))
                    df, content_sim = preprocess_csv()
                    n_products = len(product_dict)
                    second_recommendations = content_based_recommendations(product_id, content_sim, df, n_products)
                    second_ids = [item['product_id'] for item in second_recommendations]
                    previous = [product_dict[pid] for pid in second_ids if pid in product_dict][:6]

                combined = top_recommendations + previous + all_products
                seen_ids = set()
                products = []
                for p in combined:
                    if p.id not in seen_ids:
                        products.append(p)
                        seen_ids.add(p.id)
            else:
                products = Product.query.order_by(Product.clicks.desc()).all()

            return render_template('dashboard.html', hybrid_products=products, product_slideshow=product_slideshow, choice=choice)
        else:
            name = current_user.name
            products = Product.query.order_by(Product.clicks.desc()).all()
            product_slideshow = Product.query.order_by(Product.clicks.desc()).limit(6).all()
            recommended_ids = collaborating_based_recommendations(current_user.id, n_products=5)
            recommended_products = Product.query.filter(Product.id.in_(recommended_ids)).all()
            interaction = UserInteraction.query.filter_by(user_id=current_user.id).order_by(UserInteraction.clicks.desc()).first()

            if session.get('last_viewed_product_id'):
                product_id = session.get('last_viewed_product_id')
            elif current_user.last_view != 0:
                product_id = current_user.last_view
                session['last_viewed_product_id'] = product_id
            elif interaction:
                product_id = interaction.product_id
            else:
                fallback_product = Product.query.first()
                product_id = fallback_product.id if fallback_product else None

            hybrid_products = []
            product_dict = {}
            if product_id:
                n_products = Product.query.count()
                df, content_sim = preprocess_csv()
                hybrid_ids = hybrid_based_recommendations(product_id, content_sim, df, n_products)
                filtered_products = Product.query.filter(Product.id.in_(hybrid_ids)).all()
                product_dict = {product.id: product for product in filtered_products}
                hybrid_products = [product_dict[pid] for pid in hybrid_ids if pid in product_dict]

            previous = []
            if session.get('second_last_view'):
                second_id = int(session.get('second_last_view'))
                df, content_sim = preprocess_csv()
                n_products = Product.query.count()
                second_recommendations = content_based_recommendations(second_id, content_sim, df, n_products)
                second_ids = [item['product_id'] for item in second_recommendations]
                second_products = Product.query.filter(Product.id.in_(second_ids)).all()
                product_dict.update({p.id: p for p in second_products})
                previous = [product_dict[pid] for pid in second_ids if pid in product_dict]

            if not hybrid_products:
                hybrid_products = products

            seen_ids = set()
            final_products = []
            for p in hybrid_products[:10] + previous[:4] + products:
                if p.id not in seen_ids:
                    final_products.append(p)
                    seen_ids.add(p.id)

            db.session.commit()

            return render_template(
                'dashboard.html',
                name=name,
                products=products,
                product_slideshow=product_slideshow,
                recommended_products=recommended_products,
                choice=choice,
                hybrid_products=final_products
            )

@app.route('/recommend')
def recommend():
    recommended_ids = collaborating_based_recommendations(current_user.id, n_products=5)
    recommended_products = Product.query.filter(Product.id.in_(recommended_ids)).all()
    return render_template('recommend.html', recommended_products=recommended_products)

@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    products = [item.product for item in cart_items]
    cart_total = sum((item.product.price or 0) * item.quantity for item in cart_items)
    total = sum((item.product.discounted_price or 0) * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, products=products, cart_total=cart_total, total=total)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    product.clicks = (product.clicks or 0) + 1
    product.conversion_rate = (product.units_sold / product.clicks) * 100
    db.session.commit()
    existing_item = Cart.query.filter_by(user_id=current_user.id, product_id=product.id).first()

    if session.get('last_viewed_product_id'):
        session['second_last_view'] = session.get('last_viewed_product_id')
    session['last_viewed_product_id'] = product_id
    current_user.last_view = int(session.get('last_viewed_product_id'))
    
    if existing_item:
        existing_item.quantity += 1
    else:
        new_item = Cart(user_id=current_user.id, product_id=product.id)
        db.session.add(new_item)
    
    db.session.commit()
    flash("Product added to cart.", "success")
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = Cart.query.get_or_404(cart_item_id)
    db.session.delete(cart_item)
    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/clear_cart/<int:user_id>', methods=['POST'])
@login_required
def clear_cart(user_id):
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    for item in cart_items:
        db.session.delete(item)
    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/view_details/<int:product_id>')
def view_details(product_id):
    more = request.args.get('more', 'false').lower() == 'true'
    if session.get('last_viewed_product_id'):
        session['second_last_view'] = session.get('last_viewed_product_id')
    session['last_viewed_product_id'] = product_id
    current_user.last_view = int(session.get('last_viewed_product_id'))
    df, content_sim = preprocess_csv()
    n_products = len({product.id for product in (Product.query.all())})
    recommendations = content_based_recommendations(product_id, content_sim, df, n_products)
    try:
        recommendations.pop(0)
    except Exception as e:
        flash(e)
    recommendations = recommendations[:16]
    recommended_ids = [item['product_id'] for item in recommendations]
    products = Product.query.filter(Product.id.in_(recommended_ids)).all()

    product_dict = {product.id: product for product in products}
    recommended_products = [product_dict[pid] for pid in recommended_ids if pid in product_dict]
    product = Product.query.get_or_404(product_id)

    product.clicks = product.clicks + 1
    db.session.commit()
    product.conversion_rate = round((product.units_sold / product.clicks) * 100 if product.clicks else 0, 2)
    if current_user.is_authenticated:
        existing = UserInteraction.query.filter_by(user_id=current_user.id, product_id=product.id).first()
        if existing:
            existing.clicks += 1
        else:
            interaction = UserInteraction(user_id=current_user.id, product_id=product.id, clicks=1)
            db.session.add(interaction)
        db.session.commit()

    return render_template('view_details.html', product=product, recommended_products=recommended_products)

@app.route('/checkout/<int:product_id>/<int:user_id>', methods=['POST', 'GET'])
@login_required
def checkout(product_id, user_id):
    if current_user.id != user_id:
        return redirect(url_for('home'))

    product = Product.query.get_or_404(product_id)
    user = User.query.get_or_404(user_id)

    platform_fee = 4
    quantity = 1
    price = product.discounted_price if hasattr(product, 'discounted_price') else product.price
    discount = product.price - price
    subtotal = price * quantity
    delivery_charge = 0 if subtotal >= 1000 else 30
    total = subtotal + platform_fee + delivery_charge
    delivery_date = (datetime.now() + timedelta(days=4)).strftime('%b %d, %a')

    return render_template(
        "checkout.html",
        product=product,
        user=user,
        address=user.location,
        price=price,
        discount=discount,
        quantity=quantity,
        platform_fee=platform_fee,
        delivery_charge=delivery_charge,
        total=total,
        delivery_date=delivery_date
    )

@app.route('/checkout_bulk/<int:user_id>', methods=['GET', 'POST'])
@login_required
def checkout_bulk(user_id):
    user_id = int(user_id)
    if not current_user.is_authenticated or current_user.id != user_id:
        flash("You are not authorized to place this order.", "error")
        return redirect(url_for('cart'))

    cart_items = Cart.query.filter_by(user_id=user_id).all()
    if not cart_items:
        flash("Your cart is empty.", "error")
        return redirect(url_for('cart'))

    user = User.query.get_or_404(user_id)
    address = user.location
    product_ids = [item.product_id for item in cart_items]
    products = Product.query.filter(Product.id.in_(product_ids)).all()

    total_discounted_price = 0
    for item in cart_items:
        product = next((p for p in products if p.id == item.product_id), None)
        if product:
            total_discounted_price += product.discounted_price * item.quantity

    delivery_charge = 0 if total_discounted_price >= 1000 else 30
    platform_fee = 5

    return render_template(
        'checkout_bulk.html',
        products=products,
        user=user,
        address=address,
        platform_fee=platform_fee,
        delivery_charge=delivery_charge
    )

@app.route('/place_order/<user_id>', methods=['POST'])
@login_required
def place_order(user_id):
    user_id = int(user_id)
    if current_user.id != user_id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    delivery_details = user.location
    if not delivery_details:
        flash("Please provide a delivery address.", "warning")
        return redirect(url_for('edit_address', next=request.path))

    payment_method = request.form.get("payment_method")
    if not payment_method:
        flash("Please select a payment method.", "warning")
        return redirect(request.referrer or url_for('cart'))

    product_ids = request.form.getlist("product_ids")
    quantities = request.form.getlist("quantities")
    order_ids = []
    order_date = datetime.now()
    delivery_date = order_date + timedelta(days=3)

    for pid, qty in zip(product_ids, quantities):
        product = Product.query.get(int(pid))
        if not product:
            continue

        quantity = int(qty)
        discounted_price = product.discounted_price or product.price
        total_amount = round(discounted_price * quantity, 2)

    delivery_charge = 30 if round(total_amount) < 1000 else 0
    platform_fee = 5

    for pid, qty in zip(product_ids, quantities):
        product = Product.query.get(int(pid))
        if not product:
            continue

        quantity = int(qty)
        discounted_price = product.discounted_price or product.price
        total_amount = round(discounted_price * quantity + platform_fee + delivery_charge, 2)

        new_order = Order(
            user_id=user_id,
            product_id=product.id,
            delivery_details=delivery_details,
            order_date=order_date,
            delivery_date=delivery_date,
            amount=total_amount,
            payment_method=payment_method,
            img=product.image,
            delivery_charge=delivery_charge,
            quantities=quantity
        )

        db.session.add(new_order)
        db.session.flush()
        order_ids.append(new_order.id)

    db.session.commit()
    flash(f"{len(order_ids)} order(s) placed successfully!", "success")
    return redirect(url_for('order_page', order_id=order_ids[0]))

@app.route('/order/<order_id>', endpoint='order_page')
@login_required
def order_page(order_id):
    order = Order.query.get_or_404(order_id)
    product = Product.query.get_or_404(order.product_id)
    product.units_sold = (product.units_sold or 0) + order.quantities
    product.conversion_rate = (product.units_sold / product.clicks) * 100 if product.clicks else 0
    db.session.commit()
    return render_template('order.html', order=order, product=product)

@app.route('/orders_history')
@login_required
def orders_history():
    update_order_status()
    orders = Order.query.filter_by(user_id=current_user.id).order_by(desc(Order.order_date)).all()
    return render_template('orders_history.html', orders=orders, datetime=datetime, timedelta=timedelta, timezone=timezone)

@app.route('/cancell_order/<string:order_item_id>', methods=['POST'])
@login_required
def cancell_order(order_item_id):
    order_item = Order.query.get_or_404(order_item_id)
    if order_item.status not in ['Delivered', 'Cancelled']:
        order_item.status = 'Cancelled'
        order_item.delivery_date = None
        order_item.payment_method = None
        order_item.amount = 0.0
        order_item.delivery_charge = 0.0
        order_item.quantities = 0
        order_item.payment_status = 'N/A'
        order_item.delivery_details = 'N/A'
        db.session.commit()
    return redirect(url_for('orders_history'))

@app.route('/rating/<int:product_id>/<string:order_id>', methods=['GET', 'POST'])
@login_required
def rating(product_id, order_id):
    product = Product.query.get_or_404(product_id)
    existing_rating = ProductRating.query.filter_by(
        user_id=current_user.id,
        product_id=product_id,
        order_id=order_id
    ).first()
    order = Order.query.get(order_id)

    if existing_rating or order.status != 'Delivered':
        if existing_rating:
            flash("You have already rated this product for this order.", "warning")
        return redirect(url_for('view_details', product_id=product_id))

    if request.method == 'POST':
        rating_value = int(request.form.get('rating'))
        new_rating = ProductRating(
            user_id=current_user.id,
            product_id=product_id,
            order_id=order_id,
            rating_value=rating_value
        )
        db.session.add(new_rating)
        product.total_rating += rating_value
        product.rating_count += 1
        product.rating = round(product.total_rating / product.rating_count, 2)
        db.session.commit()
        flash("Thanks for rating!", "success")
        return redirect(url_for('view_details', product_id=product_id))

    return render_template('rating.html', product=product)

@app.errorhandler(404)
def page_not_found(e):
    print(e)
    return render_template("error.html", error=e)

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum size allowed is 5MB.', 'error')
    return redirect(request.url)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

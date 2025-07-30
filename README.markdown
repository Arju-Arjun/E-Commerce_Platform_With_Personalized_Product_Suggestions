# E-Commerce Platform

## Overview
This is a Flask-based e-commerce web application that supports user registration, product browsing, cart management, order processing, and product recommendations. It includes features for both users and administrators, with additional support for company accounts to manage their products. The application uses SQLite as the database and implements content-based and collaborative filtering for product recommendations.

## Features
- **User Management**: Register, login, logout, profile management, and address updates.
- **Product Management**: Admins and companies can add, edit, and delete products.
- **Cart and Orders**: Add products to cart, checkout (single or bulk), and view order history.
- **Recommendations**: Hybrid recommendation system using content-based and collaborative filtering.
- **Ratings**: Users can rate products after delivery.
- **Admin Dashboard**: Manage products, view user messages, and handle company registrations.
- **Company Dashboard**: Companies can manage their branded products.
- **Contact System**: Users can send messages, and admins can respond.

## Tech Stack
- **Backend**: Flask, Flask-SQLAlchemy, Flask-Login
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript (with Jinja2 templating)
- **Recommendation System**: scikit-learn (TF-IDF, cosine similarity)
- **Dependencies**: pandas, Werkzeug, SQLite3

## Installation
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <project-directory>
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install flask flask-sqlalchemy flask-login pandas scikit-learn
   ```

4. **Create Database**:
   Run the application to initialize the SQLite database (`db.sqlite`):
   ```bash
   python app.py
   ```

5. **Directory Structure**:
   Ensure the following folders exist:
   - `static/profile_pics`: For user profile images
   - `static/product_images`: For product images
   - `instance`: For the SQLite database (`db.sqlite`) and generated CSV (`product.csv`)

## Configuration
- **Flask Configuration**:
  - `SECRET_KEY`: Set to `'arjun#*12'` (replace with a secure key in production).
  - `SQLALCHEMY_DATABASE_URI`: Set to `"sqlite:///db.sqlite"`.
  - `UPLOAD_FOLDER`: Directory for profile pictures (`static/profile_pics`).
  - `PRODUCT_UPLOAD_FOLDER`: Directory for product images (`static/product_images`).

- **Database Models**:
  - `User`: Stores user details (name, phone, email, location, etc.).
  - `Product`: Stores product details (name, price, category, etc.).
  - `Cart`: Manages user cart items.
  - `Order`: Tracks order details (delivery, payment, status).
  - `UserInteraction`: Records user clicks for recommendations.
  - `ProductRating`: Stores product ratings.
  - `Admin`: Admin credentials for dashboard access.
  - `Company`: Company accounts for managing branded products.
  - `Contact`: Stores user messages and admin responses.

## Usage
1. **Run the Application**:
   ```bash
   python app.py
   ```
   The app runs in debug mode by default and is accessible at `http://127.0.0.1:5000`.

2. **Access Routes**:
   - `/`: Home page with product categories.
   - `/register` and `/login`: User registration and login.
   - `/dashboard`: User dashboard with product recommendations.
   - `/cart`: View and manage cart.
   - `/checkout/<product_id>/<user_id>`: Checkout for a single product.
   - `/checkout_bulk/<user_id>`: Checkout for all cart items.
   - `/orders_history`: View order history.
   - `/admin`: Admin login.
   - `/admin/dashboard`: Admin dashboard for product and message management.
   - `/company_register` and `/company/login`: Company registration and login.
   - `/company/dashboard`: Company dashboard for managing branded products.

3. **Recommendations**:
   - Uses TF-IDF and cosine similarity for content-based filtering.
   - Collaborative filtering based on user interactions (clicks).
   - Hybrid recommendations combine both approaches.

## Notes
- **Product CSV**: Generated from the `Product` table and used for recommendations (`instance/product.csv`).
- **Order Status Updates**: Automatically updates order status based on delivery dates.
- **Security**: Passwords are hashed using Werkzeug's `generate_password_hash`.
- **File Uploads**: Supports image uploads for products and user profiles (PNG, JPG, JPEG, GIF).

## Future Improvements
- Add payment gateway integration.
- Implement search functionality.
- Enhance recommendation algorithms with more user data.
- Add support for product reviews and comments.
- Improve UI/UX with a modern frontend framework (e.g., React).

## License
This project is for educational purposes and not licensed for commercial use.
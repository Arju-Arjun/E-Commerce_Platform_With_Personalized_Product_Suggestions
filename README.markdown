# 🛒 Personalized Product Recommendation System

## 📌 Project Overview
This project is a **Flask-based e-commerce web application** with an integrated **AI-powered recommendation system**.  
It provides **content-based, collaborative filtering, and hybrid recommendations** to enhance user shopping experience.  

The system includes:
- 👤 User and Admin/Company authentication
- 🛍️ Product management (add, edit, delete, offers)
- 🛒 Cart & Checkout functionality
- 📦 Order placement & tracking
- ⭐ Product ratings & reviews
- ✉️ Contact & response system
- 🔮 AI-driven personalized product recommendations

---

## 🚀 Features
- ✅ User Registration & Login (Phone/Email authentication)  
- ✅ Admin & Company Dashboards  
- ✅ Product CRUD (Create, Read, Update, Delete)  
- ✅ Cart Management (Add/Remove/Clear)  
- ✅ Checkout with Delivery & Payment options  
- ✅ Order Tracking with Status updates (Processing → Dispatched → Delivered)  
- ✅ Product Ratings & Reviews  
- ✅ Hybrid Recommendation System (Content + Collaborative)  
- ✅ Contact/Message with response system  

---

## 🛠️ Tech Stack
- **Backend:** Flask (Python)  
- **Database:** SQLite (SQLAlchemy ORM)  
- **Frontend:** HTML, CSS, JavaScript, Jinja2 Templates  
- **AI/ML:** Scikit-learn (TF-IDF, Cosine Similarity for recommendations)  
- **Authentication:** Flask-Login, Werkzeug Security  
- **Other:** Pandas, UUID, File Uploads  

---

## 📂 Project Structure

📦 project/

┣ 📜 app.py # Main Flask application

┣ 📂 templates/ # HTML templates

┣ 📂 static/

┃ ┣ 📂 profile_pics/ # User profile images

┃ ┣ 📂 product_images/ # Product images

┣ 📂 instance/

┃ ┣ 📜 db.sqlite # SQLite database

┃ ┣ 📜 product.csv # Exported product data

┣ 📜 requirements.txt # Dependencies

┣ 📜 README.md # Project Documentation





---

## ⚙️ Installation & Setup

 1️⃣ Clone Repository
```bash
git clone https://github.com/your-username/product-recommendation-system.git
cd product-recommendation-system
```
2️⃣ Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate   # On Mac/Linux
venv\Scripts\activate      # On Windows
```
3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```
4️⃣ Initialize Database

```python
>>> from app import db, app
>>> with app.app_context():
...     db.create_all()
...
```
5️⃣ Run Application
```bash
python app.py

```
The app will be available at: http://127.0.0.1:5000


## 📊 Recommendation System

The project uses three approaches:

Content-based Filtering → Uses TF-IDF on product descriptions, categories, and brand.

Collaborative Filtering → Based on user-product interactions (clicks, purchases).

Hybrid Approach → Combines both for better personalization.

## 🧑‍💻 Author

[Arjun K – Developer](https://github.com/Arju-Arjun)

📜 License

This project is licensed under the MIT License.

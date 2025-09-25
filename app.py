import os
import io
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
# ---------------- Flask App ----------------
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///realestate2.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ---------------- Database Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    wishlist = db.relationship('Wishlist', backref='user', lazy=True)


    
class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    images = db.relationship('PropertyImage', backref='property', lazy=True)

class PropertyImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)  # store image in DB
    mimetype = db.Column(db.String(50), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)

class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)

# ---------------- Routes ----------------
@app.route('/')
def home():
    return render_template('home.html')

# Registration
# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("User already exists!")
            return redirect(url_for('register'))

        # ✅ Use bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        is_admin = False
        if User.query.count() == 0:  # first registered user becomes admin
            is_admin = True

        user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        # ✅ Use bcrypt to verify password
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login successful!")
            return redirect(url_for('properties'))
        else:
            flash("Invalid credentials!")
            return redirect(url_for('login'))
    return render_template('login.html')


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('home'))

# Add Property (Admin only)
@app.route('/add_property', methods=['GET','POST'])
def add_property():
    if 'user_id' not in session:
        flash("Login first!")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash("Admin access only!")
        return redirect(url_for('home'))

    if request.method == "POST":
        name = request.form['name']
        location = request.form['location']
        price = float(request.form['price'])
        description = request.form['description']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        new_property = Property(
            name=name, location=location, price=price, description=description,
            latitude=latitude, longitude=longitude
        )
        db.session.add(new_property)
        db.session.commit()

        files = request.files.getlist('images')
        for file in files:
            if file:
                img = PropertyImage(
                    filename=file.filename,
                    data=file.read(),
                    mimetype=file.mimetype,
                    property=new_property
                )
                db.session.add(img)
        db.session.commit()
        flash("Property added successfully!")
        return redirect(url_for('property_details', property_id=new_property.id))

    return render_template('add_property.html')

# Property List
@app.route('/properties')
def properties():
 
    location = request.args.get('city', '')
 
    props = Property.query.filter(Property.location.contains(location)).all()


    # Get current logged-in user
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])

    return render_template('properties.html', properties=props, search=location, user=user)

# Property Details
@app.route('/property/<int:property_id>')
def property_details(property_id):
    prop = Property.query.get_or_404(property_id)
    return render_template('property_details.html', prop=prop)

# Serve images from database
@app.route('/image/<int:image_id>')
def image(image_id):
    img = PropertyImage.query.get_or_404(image_id)
    return send_file(
        io.BytesIO(img.data),
        mimetype=img.mimetype,
        download_name=img.filename
    )

# Wishlist
@app.route('/wishlist/add/<int:property_id>')
def add_wishlist(property_id):
    if 'user_id' not in session:
        flash("Login first!")
        return redirect(url_for('login'))

    if not Wishlist.query.filter_by(user_id=session['user_id'], property_id=property_id).first():
        db.session.add(Wishlist(user_id=session['user_id'], property_id=property_id))
        db.session.commit()
        flash("Added to wishlist!")
    return redirect(url_for('property_details', property_id=property_id))

@app.route('/wishlist')
def wishlist():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    # Fetch all wishlist items with their properties
    wishlist_items = []
    for item in user.wishlist:
        prop = Property.query.get(item.property_id)
        wishlist_items.append({'wishlist': item, 'property': prop})

    return render_template('wishlist.html', wishlist_items=wishlist_items)


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# Delete Property (Admin only)
@app.route('/property/delete/<int:property_id>', methods=['POST'])
def delete_property(property_id):
    if 'user_id' not in session:
        flash("Login first!")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash("Admin access only!")
        return redirect(url_for('home'))

    prop = Property.query.get_or_404(property_id)
    db.session.delete(prop)
    db.session.commit()
    flash("Property deleted!")
    return redirect(url_for('properties'))

# ---------------- Run App ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

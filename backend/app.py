# import os
# from flask import Flask, render_template, request, jsonify
# from pymongo import MongoClient
# from werkzeug.security import generate_password_hash  # For password hashing

# # Initialize Flask app
# app = Flask(__name__,
#             template_folder=os.path.join(os.getcwd(), 'templates'),  # Path to templates folder
#             static_folder=os.path.join(os.getcwd(), 'static'))  # Path to static folder

# # Set up MongoDB connection
# client = MongoClient("mongodb://localhost:27017/")
# db = client['raise_my_voice']
# collection = db['users']

# @app.route('/')
# def index():
#     return render_template('signup.html')  # Render the signup page

# @app.route('/post', methods=['POST'])
# def post_data():
#     try:
#         # Get the data from the request
#         data = request.get_json()  # Get the JSON data sent from the frontend

#         name = data.get('name')
#         email = data.get('email')
#         password = data.get('password')

#         # Validate the received data
#         if not name or not email or not password:
#             return jsonify({"error": "All fields are required!"}), 400

#         # Check if email already exists in the database
#         existing_user = collection.find_one({'email': email})
#         if existing_user:
#             return jsonify({"error": "Email is already registered!"}), 400

#         # Hash the password before storing it (important for security)
#         hashed_password = generate_password_hash(password, method='sha256')

#         # Insert the new user data into the MongoDB collection
#         user = {
#             'name': name,
#             'email': email,
#             'password': password
#         }
#         result = collection.insert_one(user)

#         # Return a success message after the user is created
#         return jsonify({"message": "User signed up successfully!"}), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route('/home')
# def home():
#     return render_template('home.html')  # Render the home page after successful signup
# @app.route('/about')
# def about():
#     return render_template('about.html')

# @app.route('/laws')
# def laws():
#     return render_template('laws.html')

# @app.route('/contact')
# def contact():
#     return render_template('contact.html')

# @app.route('/profile')
# def profile():
#     return render_template('profile.html')
import os
from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient

# Initialize Flask app
app = Flask(__name__,
            template_folder=os.path.join(os.getcwd(), 'templates'),  # Path to templates folder
            static_folder=os.path.join(os.getcwd(), 'static'))  # Path to static folder

# Set up MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['raise_my_voice']
collection = db['users']

@app.route('/')
def index():
    return render_template('signup.html')  # Render the signup page

@app.route('/post', methods=['POST'])
def post_data():
    try:
        # Get the data from the request
        data = request.get_json()  # Get the JSON data sent from the frontend

        name = data.get('name')
        email = data.get('email')
        password = data.get('password')

        # Validate the received data
        if not name or not email or not password:
            return jsonify({"error": "All fields are required!"}), 400

        # Check if email already exists in the database
        existing_user = collection.find_one({'email': email})
        if existing_user:
            return jsonify({"error": "Email is already registered!"}), 400

        # Insert the new user data into the MongoDB collection with the plain password
        user = {
            'name': name,
            'email': email,
            'password': password  # Store the plain password, not hashed
        }
        collection.insert_one(user)

        # Return a success message after the user is created
        return jsonify({"message": "User signed up successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/home')
def home():
    return render_template('home.html')  # Render the home page after successful signup

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/laws')
def laws():
    return render_template('laws.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

if __name__ == "__main__":
    app.run(debug=True)

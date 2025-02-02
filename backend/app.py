import os
from flask import Flask, render_template, request, jsonify, url_for
from pymongo import MongoClient
from flask_cors import CORS
from datetime import datetime
import pytz

app = Flask(__name__)
CORS(app)
 
# Initialize Flask app
app = Flask(__name__,
            template_folder=os.path.join(os.getcwd(), 'templates'),  # Path to templates folder
            static_folder=os.path.join(os.getcwd(), 'static'))  # Path to static folder

# Set up MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['raise_my_voice']
user_collection = db['users']  # Collection for users (remain unchanged)
complaint_collection = db['complainant_login']  # Correct collection name for complaints

@app.route('/')
def index():
    return render_template('index.html')  # Render the index page

@app.route('/signup', methods=['GET', 'POST'])
def signup():
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
        existing_user = user_collection.find_one({'email': email})  # Corrected here
        if existing_user:
            return jsonify({"error": "Email is already registered!"}), 400

        # Insert the new user data into the MongoDB collection with plain text password
        user = {
            'name': name,
            'email': email,
            'password': password  # Store the password as plain text (consider hashing it later)
        }
        user_collection.insert_one(user)  # Corrected here

        # Return success message after the user is created
        return jsonify({"message": "User signed up successfully! You can now log in."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()  # Get JSON data sent from the frontend
        email = data.get('email')
        password = data.get('password')

        # Validate the received data
        if not email or not password:
            return jsonify({"error": "Both email and password are required!"}), 400

        # Find user by email in the 'users' collection
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({"error": "User not found. Please sign up!"}), 404

        # Check if the password matches
        if user['password'] != password:  # Direct comparison of plain text password
            return jsonify({"error": "Incorrect password!"}), 400

        # If credentials are correct, return success
        return jsonify({"message": "Login successful!"}), 200
    
    # For GET requests, render the login page
    return render_template('login.html')
 

@app.route('/complaintlogin')
def complaintlogin():
    return render_template('complaint/complaintlogin.html')    


@app.route('/complaint/register', methods=['POST'])
def register_complaint():
    try:
        data = request.get_json()  # Receive the data sent from the frontend
        name = data.get('name')
        mobile = data.get('mobile')
        captcha = data.get('captcha')
        otp = data.get('otp')

        # Capture current date and time for the complaint's "joined" field
        timezone = pytz.timezone("Asia/Kolkata")  # Adjust the timezone as per your requirements
        joined_date = datetime.now(timezone).strftime("%Y-%m-%d %H:%M:%S")

        # Validate the received data
        if not name or not mobile or not captcha or not otp:
            return jsonify({"error": "All fields are required!"}), 400

        # Insert complaint into MongoDB, including latitude and longitude
        complaint = {
            'name': name,
            'mobile': mobile,
            'joined': joined_date
        }
        result = complaint_collection.insert_one(complaint)

        return jsonify({"message": "Complaint registered successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route for the dashboard with search and pagination
@app.route('/dashboard', methods=['GET'])
def dashboard():
    try:
        search_query = request.args.get('search_query', '')

        # Count distinct users based on their 'mobile' field
        total_cases = complaint_collection.distinct('mobile')
        total_cases_count = len(total_cases)

        # Search functionality
        if search_query:
            recent_complaints = complaint_collection.find({
                '$or': [
                    {'name': {'$regex': search_query, '$options': 'i'}},  # Case-insensitive search
                    {'mobile': {'$regex': search_query, '$options': 'i'}},
                    {'joined': {'$regex': search_query, '$options': 'i'}}
                ]
            }).sort('joined', -1)
        else:
            recent_complaints = complaint_collection.find({}).sort('joined', -1)

        # Convert the cursor to a list before slicing
        recent_complaints_list = list(recent_complaints)

        # Pagination logic
        page = int(request.args.get('page', 1))
        per_page = 10
        start = (page - 1) * per_page
        end = page * per_page
        total_complaints = recent_complaints_list[start:end]

        return render_template('admindash.html', total_cases=total_cases_count, recent_complaints=total_complaints, page=page, per_page=per_page, search_query=search_query)

    except Exception as e:
        print(f"Error occurred: {e}")  # Print the error to the console
        return f"Error occurred: {e}"  # Show the error message in the browser for debugging purposes


@app.route('/complaintdetails')
def complaint_details():
    return render_template('complaint/complaintdetails.html')

@app.route('/complaintsubmission')
def complaint_submit():
    return render_template('complaint/submission.html')

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

if __name__ == '__main__':
    app.run(debug=True)




import os
from flask import Flask, render_template, request, jsonify,send_from_directory,abort
from werkzeug.utils import secure_filename, safe_join
from pymongo import MongoClient
from flask_cors import CORS
import random
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import pytz
import pymongo
import time
from pymongo import WriteConcern
from bson.objectid import ObjectId
app = Flask(__name__, 
            template_folder=os.path.join(os.getcwd(), 'templates'),  # Path to templates folder
            static_folder=os.path.join(os.getcwd(), 'static'))  # Path to static folder

# Enable CORS for all origins
CORS(app)

####################################################################################################
# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['raise_my_voice']
user_collection = db['users']
otp_collection = db['otp_codes']  # Collection for OTP data
complaint_collection = db['complainant_login']  # Correct collection name for complaints
# Function to validate email format
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# Function to send OTP email
def send_otp_email(recipient_email, otp_code):
    sender_email = "22csec05@gmail.com"  # Replace with your Gmail address
    sender_password = "infx yxzh ukdu meno"  # Replace with your Gmail app password

    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    subject = "Your OTP Code"
    body = f"Your OTP code is {otp_code}. Please enter it on the website to verify your email."

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        # Connect to the Gmail SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit()
        print(f"OTP sent successfully to {recipient_email}")
    except Exception as e:
        print(f"Error sending email: {e}")
        raise e
#######################################################################################
@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')  # Render the signup page

# Route for handling signup POST (for OTP sending)
@app.route('/signup', methods=['POST'])
def signup_post():
    try:
        data = request.get_json()  # Get JSON data from the frontend
        email = data.get('email')  # Extract email

        # Validate email format (optional)
        if not email:
            return jsonify({"error": "Email is required!"}), 400

        # Check if email already exists in the database
        existing_user = user_collection.find_one({'email': email})
        if existing_user:
            return jsonify({"error": "Email is already registered!"}), 400

        # Generate OTP
        otp_code = str(random.randint(100000, 999999))

        # Store OTP in the database with timestamp for expiration check
        otp_collection.insert_one({
            'email': email,
            'otp_code': otp_code,
            'created_at': time.time()  # Store the timestamp
        })

        # Send OTP to the user's email
        send_otp_email(email, otp_code)

        return jsonify({"message": "OTP sent successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to verify OTP and store the user data
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()  # Get JSON data from the frontend
        print(f"Received data: {data}")  # Debugging line to check what is being received

        # Extract data
        email = data.get('email')
        otp_code = data.get('otp')
        password = data.get('password')
        name = data.get('name')  # Get the user's name

        # Check if all fields are provided
        if not email or not otp_code or not password or not name:
            print(f"Missing data: email={email}, otp_code={otp_code}, password={password}, name={name}")  # Debugging line
            return jsonify({"error": "Email, OTP, password, and name are required!"}), 400

        # Look for the OTP entry in the otp_collection
        otp_entry = otp_collection.find_one({'email': email, 'otp_code': otp_code})

        # Check if OTP exists
        if not otp_entry:
            return jsonify({"error": "Invalid OTP or OTP expired!"}), 400

        # Check if the OTP has expired (5 minutes expiration)
        if time.time() - otp_entry['created_at'] > 300:
            otp_collection.delete_one({'_id': otp_entry['_id']})  # Clean up expired OTP
            return jsonify({"error": "OTP has expired!"}), 400

        # Now that OTP is valid, we can proceed to store the user data
        user = {
            'email': email,
            'password': password,  # Store the password as plain text
            'name': name  # Store the name as well
        }

        # Insert the user data into the 'users' collection
        result = user_collection.insert_one(user)

        # Check the result of the insertion
        if result.inserted_id:
            # OTP verification successful, clean up the OTP
            otp_collection.delete_one({'_id': otp_entry['_id']})

            return jsonify({"message": "User successfully signed up!"}), 200
        else:
            return jsonify({"error": "Failed to save user in database!"}), 500

    except Exception as e:
        print(f"Error during OTP verification: {e}")  # Debugging line
        return jsonify({"error": str(e)}), 500



#######################################################################################
@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')  # Render the login page

# Route for handling OTP sending for login
@app.route('/send-otp-login', methods=['POST'])
def send_otp_login():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"error": "Email is required!"}), 400

        # Check if email exists in the database
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({"error": "User not found!"}), 400

        # Generate OTP
        otp_code = str(random.randint(100000, 999999))
        created_at = time.time()

        # Store OTP in the database with expiration time
        otp_collection.insert_one({
            'email': email,
            'otp_code': otp_code,
            'created_at': created_at
        })

        # Send OTP to the user's email
        send_otp_email(email, otp_code)

        return jsonify({"message": "OTP sent to your email!"}), 200

    except Exception as e:
        print(f"Error in /send-otp-login route: {e}")
        return jsonify({"error": str(e)}), 500

# Route for login (with OTP verification and password check)
@app.route('/login', methods=['POST'])
def login_post():
    try:
        data = request.get_json()  # Get JSON data from the frontend
        email = data.get('email')
        password = data.get('password')
        otp_code = data.get('otp')  # Include OTP in the request

        # Check if email, password, and OTP are provided
        if not email or not password or not otp_code:
            return jsonify({"error": "Email, password, and OTP are required!"}), 400

        # Find user by email
        user = user_collection.find_one({'email': email})

        if not user:
            return jsonify({"error": "User not found!"}), 400

        # Find OTP entry by email and OTP code
        otp_entry = otp_collection.find_one({'email': email, 'otp_code': otp_code})

        if not otp_entry:
            return jsonify({"error": "Invalid OTP or OTP expired!"}), 400

        # Check if the OTP has expired (5 minutes expiration)
        if time.time() - otp_entry['created_at'] > 300:
            otp_collection.delete_one({'_id': otp_entry['_id']})  # Clean up expired OTP
            return jsonify({"error": "OTP has expired!"}), 400

        # Check if the provided password matches the stored password
        if user['password'] != password:  # Compare plain text password
            return jsonify({"error": "Invalid password!"}), 400

        # OTP verification successful and password matches
        return jsonify({"message": "Login successful!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#######################################################################################
# Render index page (home page)
@app.route('/')
def index():
    return render_template('index.html')
#######################################################################################################

@app.route('/complaintlogin')
def complaintlogin():
    return render_template('complaint/complaintlogin.html')    

@app.route('/send-otp-complaint', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email or '@' not in email:
            return jsonify({"error": "Please provide a valid email address!"}), 400

        otp_code = str(random.randint(100000, 999999))
        send_otp_email(email, otp_code)
        return jsonify({"message": "OTP sent successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
   
@app.route('/complaint/register', methods=['POST'])
def register_complaint():
    try:
        data = request.get_json()  # Receive data from the frontend
        name = data.get('name')
        email = data.get('email')  # Use email instead of mobile
        captcha = data.get('captcha')
        otp = data.get('otp')

        # Capture current date and time
        timezone = pytz.timezone("Asia/Kolkata")
        joined_date = datetime.now(timezone).strftime("%Y-%m-%d %H:%M:%S")

        # Validate the received data
        if not name or not email or not captcha or not otp:
            return jsonify({"error": "All fields are required!"}), 400

        # Insert complaint into MongoDB
        complaint = {
            'name': name,
            'email': email,  # Store email
            'joined': joined_date
        }
        result = complaint_collection.insert_one(complaint)

        return jsonify({"message": "Complaint registered successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

######################################################################################################


@app.route('/dashboard', methods=['GET'])
def dashboard():
    try:
        search_query = request.args.get('search_query', '')
        status_filter = request.args.get('status', 'all')  # Status filter (all, resolved, pending)

        # Get total cases
        total_cases = complaint_collection.count_documents({})

        # Count distinct resolved cases
        total_resolved = complaint_collection.count_documents({'status': 'resolved'})

        # Count distinct pending cases
        total_pending = total_cases - total_resolved

        # Build the filter condition based on the status
        filter_condition = {}
        if status_filter == 'resolved':
            filter_condition['status'] = 'resolved'
        elif status_filter == 'inactive':
            filter_condition['status'] ={'$in': ['inactive', None]}

        # Debugging: Print the filter condition
        print(f"Filter Condition: {filter_condition}")

        # Search functionality
        if search_query:
            # If there's a search query, add it to the filter
            search_condition = {
                '$or': [
                    {'name': {'$regex': search_query, '$options': 'i'}},  # Search by name
                    {'email': {'$regex': search_query, '$options': 'i'}},  # Search by email
                    {'joined': {'$regex': search_query, '$options': 'i'}}  # Search by joined date
                ]
            }
            # Merge the search condition with the status filter
            filter_condition = {**filter_condition, **search_condition}

        # Fetch complaints based on the combined filter
        recent_complaints = complaint_collection.find(filter_condition).sort('joined', -1)

        # Pagination logic
        page = int(request.args.get('page', 1))
        per_page = 10
        start = (page - 1) * per_page
        end = page * per_page

        total_complaints = list(recent_complaints)[start:end]

        return render_template(
            'admindash.html',
            total_cases=total_cases,
            total_resolved=total_resolved,
            total_pending=total_pending,
            recent_complaints=total_complaints,
            page=page,
            per_page=per_page,
            search_query=search_query,
            status_filter=status_filter  # Ensure status filter is passed to the front-end
        )

    except Exception as e:
        return f"Error occurred: {e}"

@app.route('/update_status/<complaint_id>', methods=['POST'])
def update_status(complaint_id):
    try:
        data = request.get_json()
        status = data.get('status')

        # Ensure complaint_id is valid
        if not ObjectId.is_valid(complaint_id):
            return jsonify({'success': False, 'error': 'Invalid complaint ID'})

        # Get the current status of the complaint
        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            return jsonify({'success': False, 'error': 'Complaint not found'})

        current_status = complaint.get('status')

        # Only update if the status is changing
        if status != current_status:
            # Update the complaint status
            complaint_collection.update_one(
                {'_id': ObjectId(complaint_id)},
                {'$set': {'status': status, 'updated_at': datetime.utcnow()}}
            )

            # Get the updated counts
            total_cases = complaint_collection.count_documents({})
            total_resolved = complaint_collection.count_documents({'status': 'resolved'})

            # Calculate pending as the difference between total cases and resolved
            total_pending = total_cases - total_resolved

            return jsonify({
                'success': True,
                'total_resolved': total_resolved,
                'total_pending': total_pending
            })
        else:
            return jsonify({'success': False, 'message': 'Status is already the same'})

    except Exception as e:
        # In case of any errors, log the exception and return an error message
        print(f"Error: {str(e)}")  # Log the error for debugging
        return jsonify({'success': False, 'error': str(e)})






#############################################################################################


DOCUMENTS_FOLDER = os.path.join(app.static_folder, 'documents')

# Route to serve the files
@app.route('/download/<filename>')
def download_file(filename):
    try:
        # Ensure the file exists in the correct folder
        file_path = safe_join(DOCUMENTS_FOLDER, filename)
        return send_from_directory(DOCUMENTS_FOLDER, filename, as_attachment=True)
    except Exception as e:
        # Return a 404 error if the file doesn't exist
        abort(404)
        
#############################################################################################

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
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, Response, send_from_directory, abort
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
import uuid
import json
import calendar
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename, safe_join
from bson import ObjectId
from functools import wraps
from PIL import Image
import io
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import random
import string
import math
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from flask_pymongo import PyMongo
from flask_session import Session
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_mail import Mail, Message
import humanize
import pytz
import time
from pymongo import WriteConcern

# Ensure JSON response for API routes
def json_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            response = f(*args, **kwargs)
            if isinstance(response, tuple):
                data, status_code = response
                return Response(json.dumps(data), status=status_code, mimetype='application/json')
            return Response(json.dumps(response), mimetype='application/json')
        except Exception as e:
            error_response = {'success': False, 'message': str(e)}
            return Response(json.dumps(error_response), status=500, mimetype='application/json')
    return decorated_function

# Initialize Flask app
app = Flask(__name__, 
            template_folder=os.path.join(os.getcwd(), 'templates'),  # Path to templates folder
            static_folder=os.path.join(os.getcwd(), 'static'))      # Path to static folder

# Basic configuration
app.secret_key = 'SHini260426'

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
app.config['SESSION_COOKIE_NAME'] = 'session'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# CSRF configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'SHini260426'

# Initialize extensions
sess = Session()
sess.init_app(app)
CORS(app)
csrf = CSRFProtect(app)

############################### database  and configurations #####################################################################
client = MongoClient("mongodb://localhost:27017/")
db = client['raise_my_voice']
user_collection = db['users']
otp_collection = db['otp_codes']  
complaint_collection = db["complaints"]
nodal_collection = db['nodal_officers']
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'shini.vtg622026@gmail.com'  
app.config['MAIL_PASSWORD'] = 'nufq meqd hdog qeuz'  
app.config['MAIL_DEFAULT_SENDER'] = 'shini.vtg622026@gmail.com'
mail = Mail(app)

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size_str(file_path):
    size_bytes = os.path.getsize(file_path)
    return humanize.naturalsize(size_bytes)

def save_file_with_unique_name(file):
    """Save file with a unique name to prevent overwriting"""
    original_filename = secure_filename(file.filename)
    name, ext = os.path.splitext(original_filename)
    counter = 1
    filename = original_filename
    
    # Keep trying new filenames until we find one that doesn't exist
    while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        filename = f"{name}_{counter}{ext}"
        counter += 1
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    return filename, file_path

# Google OAuth Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
GOOGLE_CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), "client_secrets.json")

# Update the google_login route
@app.route('/google-login')
def google_login():
    try:
        # Create flow instance to manage OAuth 2.0 Authorization
        flow = Flow.from_client_secrets_file(
            GOOGLE_CLIENT_SECRETS_FILE,
            scopes=[
                'https://www.googleapis.com/auth/userinfo.profile',
                'https://www.googleapis.com/auth/userinfo.email'
            ],
            redirect_uri=url_for('callback', _external=True)
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        print(f"Error in google_login: {str(e)}")
        flash('Error connecting to Google. Please try again.')
        return redirect(url_for('login'))

# Update the callback route
@app.route('/callback')
def callback():
    try:
        state = session.get('state')
        if not state:
            raise ValueError("State not found in session")

        flow = Flow.from_client_secrets_file(
            GOOGLE_CLIENT_SECRETS_FILE,
            scopes=[
                'https://www.googleapis.com/auth/userinfo.profile',
                'https://www.googleapis.com/auth/userinfo.email'
            ],
            state=state
        )
        flow.redirect_uri = url_for('callback', _external=True)

        # Get authorization code from callback
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        # Get user info from token
        credentials = flow.credentials
        token_request = requests.Request()
        
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            flow.client_config['client_id']
        )

        # Get user info
        email = id_info.get('email')
        name = id_info.get('name')
        
        if not email:
            raise ValueError("Email not provided by Google")

        # Check if user exists
        user = user_collection.find_one({'email': email})
        
        if not user:
            # Create new user
            user = {
                '_id': ObjectId(),
                'email': email,
                'name': name,
                'google_id': id_info['sub'],
                'created_at': datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
            }
            user_collection.insert_one(user)
        
        # Set session
        session['user_id'] = str(user['_id'])
        session['email'] = email
        session['name'] = name
        
        flash('Successfully logged in with Google!', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        print(f"Error in callback: {str(e)}")
        flash('Error during Google authentication. Please try again.', 'error')
        return redirect(url_for('login'))

#######################################################################################################
# Function to validate email format
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None
# Function to send OTP email
def send_otp_email(recipient_email, otp_code):
    sender_email = "shini.vtg622026@gmail.com"  # Replace with your Gmail address
    sender_password = "nufq meqd hdog qeuz"  # Replace with your Gmail app password
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    subject = "Your OTP Code"
    body = f"""
    Your OTP code is {otp_code}. Please enter it on the website to verify your email.
    """
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
@app.route('/send-otp-signup', methods=['POST'])
@csrf.exempt  # Temporarily exempt this route from CSRF protection while we debug
def send_otp_signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Generate OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store OTP in database with timestamp
        otp_collection.update_one(
            {'email': email},
            {
                '$set': {
                    'otp': otp,
                    'created_at': datetime.now(),
                    'purpose': 'signup'
                }
            },
            upsert=True
        )

        try:
            # Send email using Flask-Mail
            msg = Message(
                'Signup OTP - Raise My Voice',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"""
            Your OTP for signup is: {otp}
            
            This OTP will expire in 5 minutes.
            If you didn't request this OTP, please ignore this email.
            """
            
            mail.send(msg)
            
            return jsonify({
                'message': 'OTP sent successfully!',
                'email': email
            })
            
        except Exception as mail_error:
            print(f"Mail Error: {str(mail_error)}")
            return jsonify({'error': 'Failed to send email'}), 500
        
    except Exception as e:
        print(f"Error sending OTP: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/verify-and-signup', methods=['POST'])
@csrf.exempt  # Temporarily exempt this route from CSRF protection while we debug
def verify_and_signup():
    try:
        # Get form data
        email = request.form.get('email')
        otp = request.form.get('otp')
        password = request.form.get('password')
        
        if not email or not otp or not password:
            return jsonify({'error': 'Email, OTP and password are required'}), 400

        # Verify OTP
        stored_otp = otp_collection.find_one({
            'email': email,
            'purpose': 'signup'
        })

        if not stored_otp:
            return jsonify({'error': 'No OTP found for this email'}), 400

        if stored_otp['otp'] != otp:
            return jsonify({'error': 'Invalid OTP'}), 400

        # Check if OTP is expired (5 minutes)
        otp_time = stored_otp['created_at']
        if datetime.now() - otp_time > timedelta(minutes=5):
            return jsonify({'error': 'OTP has expired'}), 400

        # Create new user with hashed password
        user_data = {
            'email': email,
            'firstName': request.form.get('firstName'),
            'lastName': request.form.get('lastName'),
            'dateOfBirth': request.form.get('dateOfBirth'),
            'gender': request.form.get('gender'),
            'phone': request.form.get('phone'),
            'address': request.form.get('address'),
            'city': request.form.get('city'),
            'state': request.form.get('state'),
            'pincode': request.form.get('pincode'),
            'organization': request.form.get('organization'),
            'password': generate_password_hash(password),  # Hash the password
            'created_at': datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save profile document if provided
        if 'profile-document' in request.files:
            file = request.files['profile-document']
            if file and allowed_file(file.filename):
                filename, file_path = save_file_with_unique_name(file)
                user_data['profile_document'] = filename
                user_data['profile_document_size'] = get_file_size_str(file_path)

        # Insert user into database
        result = user_collection.insert_one(user_data)
        
        if result.inserted_id:
            # Set session data
            session['user_id'] = str(result.inserted_id)
            session['email'] = email
            session['name'] = f"{user_data['firstName']} {user_data['lastName']}"
            
            # Delete used OTP
            otp_collection.delete_one({'email': email, 'purpose': 'signup'})
            
            return jsonify({
                'success': True,
                'message': 'Registration successful'
            })
        else:
            return jsonify({'error': 'Failed to create user'}), 500

    except Exception as e:
        print(f"Error in signup: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.form
        email = data.get('email')
        stored_otp = otp_collection.find_one({'email': email, 'purpose': 'signup'})

        if not stored_otp or data.get('otp') != stored_otp['otp']:
            return jsonify({'success': False, 'message': 'Invalid OTP'}), 400

        # Handle file upload
        if 'profile-document' in request.files:
            file = request.files['profile-document']
            if file and allowed_file(file.filename):
                filename, file_path = save_file_with_unique_name(file)
                
                # Get file information
                file_size = get_file_size_str(file_path)
                file_type = file.content_type
                
                # Create user document with file information
                user_data = {
                    'email': email,
                    'name': data.get('name'),
                    'password': generate_password_hash(data.get('password')),  # Hash the password
                    'dob': data.get('dob'),
                    'gender': data.get('gender'),
                    'city': data.get('city'),
                    'state': data.get('state'),
                    'pincode': data.get('pincode'),
                    'organization_category': data.get('organizationCategory'),
                    'organization_role': data.get('organizationRole'),
                    'document_url': url_for('static', filename=f'uploads/{filename}', _external=True),
                    'document_name': os.path.basename(file.filename),  # Original filename
                    'document_type': file_type,
                    'document_size': file_size,
                    'document_path': f'uploads/{filename}',  # Store relative path
                    'created_at': datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                return jsonify({'success': False, 'message': 'Invalid file type'}), 400
        else:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400

        # Save user to database
        result = user_collection.insert_one(user_data)
        
        if result.inserted_id:
            # Clear OTP after successful verification
            otp_collection.delete_one({'_id': stored_otp['_id']})
            
            # Set session data
            session['user_id'] = str(result.inserted_id)
            session['email'] = email
            session['name'] = data.get('name')
            
            return jsonify({'success': True, 'redirect': url_for('login')})

    except Exception as e:
        print(f"Error in verify_otp: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

########################### Login functionalities ############################################################
@app.route('/')
def root():
    # If user is already logged in, redirect to home
    if 'user_id' in session:
        return redirect(url_for('home'))
    # Otherwise, show the index page
    return render_template('index.html')

@app.route('/index')
def index():
    # If user is already logged in, redirect to home
    if 'user_id' in session:
        return redirect(url_for('home'))
    # Otherwise, show the index page
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # If user is already logged in, redirect to home
        if 'user_id' in session:
            return redirect(url_for('home'))
        return render_template('login.html')
        
    try:
        print("Received login request")  # Debug log
        
        # Check if the request has JSON data
        if not request.is_json:
            print("Request is not JSON")  # Debug log
            return jsonify({'success': False, 'message': 'Invalid request format'}), 400
            
        data = request.get_json()
        if not data:
            print("No JSON data received")  # Debug log
            return jsonify({'success': False, 'message': 'No data received'}), 400
            
        print(f"Request data: {data}")  # Debug log
        
        email = data.get('email')
        password = data.get('password')
        otp = data.get('otp')
        
        print(f"Email: {email}, Password length: {len(password) if password else 0}, OTP: {otp}")  # Debug log
        
        if not all([email, password, otp]):
            print("Missing email, password or OTP")  # Debug log
            return jsonify({'success': False, 'message': 'Please enter email, password and OTP'}), 400
            
        # Verify user exists
        user = user_collection.find_one({'email': email})
        print(f"Found user: {user is not None}")  # Debug log
        
        if not user:
            print(f"No user found with email: {email}")  # Debug log
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
        # Verify password
        if user['password'] != password:
            print("Password mismatch")  # Debug log
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Verify OTP
        stored_otp = otp_collection.find_one({
            'email': email,
            'purpose': 'login',
            'is_used': False,
            'expiry': {'$gt': datetime.now(pytz.timezone("Asia/Kolkata"))}
        })
        
        print(f"Found OTP record: {stored_otp is not None}")  # Debug log
        if stored_otp:
            print(f"Stored OTP expiry: {stored_otp.get('expiry')}")  # Debug log
            print(f"Current time: {datetime.now(pytz.timezone('Asia/Kolkata'))}")  # Debug log
            print(f"OTP match: {stored_otp.get('otp') == otp}")  # Debug log
        
        if not stored_otp:
            print("No valid OTP found")  # Debug log
            return jsonify({'success': False, 'message': 'No valid OTP found. Please request a new OTP.'}), 401
            
        if stored_otp['otp'] != otp:
            print("OTP mismatch")  # Debug log
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 401
            
        # Mark OTP as used
        otp_collection.update_one(
            {'_id': stored_otp['_id']},
            {'$set': {'is_used': True}}
        )
            
        # If everything is valid, create session
        session['user_id'] = str(user['_id'])
        session['email'] = email
        session['name'] = user.get('name', '')
        session.permanent = True
        
        print("Login successful")  # Debug log
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'name': user.get('name', ''),
            'redirect': url_for('home')
        })
        
    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug log
        import traceback
        traceback.print_exc()  # Print full error traceback
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/home')
def home():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        # Get user details from database
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            session.clear()
            return redirect(url_for('login'))
            
        return render_template('home.html', user=user)
    except Exception as e:
        print(f"Error loading home page: {str(e)}")
        session.clear()
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/send-otp-login', methods=['POST'])
def send_otp_login():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Check if user exists for login
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'error': 'User not found with this email'}), 404

        # Generate OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store OTP in database
        otp_collection.update_one(
            {'email': email},
            {
                '$set': {
                    'otp': otp,
                    'created_at': datetime.now(),
                    'purpose': 'login',
                    'expiry': datetime.now(pytz.timezone("Asia/Kolkata")) + timedelta(minutes=5),
                    'is_used': False
                }
            },
            upsert=True
        )

        # Send email
        msg = Message(
            'Login OTP - Raise My Voice',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"""
        Your OTP for login is: {otp}
        
        This OTP will expire in 5 minutes.
        If you didn't request this OTP, please ignore this email.
        """
        
        mail.send(msg)
        
        return jsonify({
            'message': 'OTP sent successfully!',
            'email': email
        })
        
    except Exception as e:
        print(f"Error sending OTP: {str(e)}")
        return jsonify({'error': str(e)}), 500

##################################### complaint  functionalities ##############################################################################
otp_store = {}
# Timezone Setup
IST = pytz.timezone("Asia/Kolkata")
@app.route('/complaintlogin')
def complaint_login():
    return render_template('complaint/complaintlogin.html')
@app.route('/send-otp-complaint', methods=['POST'])
def send_otp_complaint():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Generate OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store OTP in database with timestamp
        otp_collection.update_one(
            {'email': email},
            {
                '$set': {
                    'otp': otp,
                    'created_at': datetime.now(),
                    'purpose': 'complaint',
                    'expiry': datetime.now(pytz.timezone("Asia/Kolkata")) + timedelta(minutes=5),
                    'is_used': False
                }
            },
            upsert=True
        )

        try:
            msg = Message(
                'Complaint Registration OTP - Raise My Voice',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"""
Dear User,

Your OTP for complaint registration is: {otp}

This OTP will expire in 5 minutes.
If you didn't request this OTP, please ignore this email.

Best regards,
Raise My Voice Team
"""
            mail.send(msg)
            
            return jsonify({
                'message': 'OTP sent successfully!',
                'email': email
            })
            
        except Exception as mail_error:
            print(f"Mail Error: {str(mail_error)}")
            return jsonify({'error': 'Failed to send email'}), 500
        
    except Exception as e:
        print(f"Error sending OTP: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/complaint/register', methods=['POST'])
def register_complaint():
    if 'email' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'GET':
        # Get pre-filled data from query parameters
        prefilled_data = {
            'name': request.args.get('name', ''),
            'email': request.args.get('email', ''),
            'phone': request.args.get('phone', ''),
            'address': request.args.get('address', '')
        }
        return render_template('register_complaint.html', prefilled_data=prefilled_data)
        
    try:
        # Handle POST request for form submission
        data = request.form
        
        complaint = {
            'user_id': session['user_id'],
            'name': data.get('name'),
            'email': data.get('email'),
            'phone': data.get('phone'),
            'address': data.get('address'),
            'complaint_text': data.get('complaint_text'),
            'status': 'Pending',
            'created_at': datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        complaint_collection.insert_one(complaint)
        flash('Complaint registered successfully!', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        print(f"Error in register_complaint: {str(e)}")
        flash('An error occurred while registering your complaint.', 'error')
        return redirect(url_for('home'))

@app.route('/complaintdetails')
def complaint_details():
    return render_template('complaint/complaintdetails.html')
@app.route('/submit_details', methods=['POST'])
def submit_details():
    try:
        data = request.get_json()
        
        # Store the details in session
        session['complaint_details'] = {
            'first_name': data['first_name'],
            'middle_name': data['middle_name'],
            'last_name': data['last_name'],
            'dob': data['dob'],
            'gender': data['gender'],
            'email': data['email'],
            'city': data['city'],
            'state': data['state'],
            'pincode': data['pincode'],
            'organization': data['organization']
        }

        # Get complaint ID from session
        complaint_id = session.get('complaint_id')
        if not complaint_id:
            return jsonify({'error': 'No active complaint session'}), 400

        # Update complaint in database with details
        update_data = {
            'details': {
                'personal_info': {
                    'first_name': data['first_name'],
                    'middle_name': data['middle_name'],
                    'last_name': data['last_name'],
                    'full_name': f"{data['first_name']} {data['middle_name']} {data['last_name']}.strip()",
                    'dob': data['dob'],
                    'gender': data['gender']
                },
                'contact_info': {
                    'email': data['email'],
                    'city': data['city'],
                    'state': data['state'],
                    'pincode': data['pincode']
                },
                'organization': data['organization']
            }
        }

        # Update the complaint document
        result = complaint_collection.update_one(
            {'_id': ObjectId(complaint_id)},
            {'$set': update_data}
        )

        if result.modified_count:
            return jsonify({'success': True, 'message': 'Details saved successfully'})
        else:
            return jsonify({'error': 'Failed to save details'}), 500
            
    except Exception as e:
        print(f"Error in submit_details: {str(e)}")
        return jsonify({'error': str(e)}), 400
@app.route('/complaintsubmission', methods=['GET', 'POST'])
def complaint_submission():
    if request.method == 'GET':
        if 'complaint_id' not in session:
            return redirect(url_for('complaint_login'))
        return render_template('complaint/submission.html')
    
    try:
        if 'complaint_id' not in session:
            return jsonify({"error": "No active complaint session"}), 401

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Required fields validation
        required_fields = ['complainant_name', 'submission_date', 'complaint']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Update complaint in database
        update_data = {
            "submission": {
                "complainant_name": data['complainant_name'],
                "submission_date": data['submission_date'],
                "on_behalf": data.get('on_behalf', ''),
                "complaint_text": data['complaint'],
                "submitted_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
            },
            "status": "Submitted"
        }

        result = complaint_collection.update_one(
            {"_id": ObjectId(session['complaint_id'])},
            {"$set": update_data}
        )

        if result.modified_count:
            return jsonify({
                "message": "Complaint submitted successfully!",
                "complaint_id": session['complaint_id']
            })
        else:
            return jsonify({"error": "Failed to update complaint"}), 500

    except Exception as e:
        print(f"Error in complaint submission: {str(e)}")
        return jsonify({"error": str(e)}), 500
####################################   track complaint  ##############################################################################
@app.route("/trackcomplaint/<complaint_id>")
def track_complaint(complaint_id):
    complaint = complaint_collection.find_one({"_id": ObjectId(complaint_id)})
    if complaint:
        return render_template("trackcomplaint.html", complaint=complaint)
    else:
        return "Complaint not found", 404
#####################################  about page #######################################################################
@app.route('/about')
def about():
    return render_template('about.html')
#####################################   laws page #######################################################################
@app.route('/laws')
def laws():
    return render_template('laws.html')
#####################################  contact  page #######################################################################
@app.route('/contact')
def contact():
    return render_template('contact.html')
#####################################  profile page #######################################################################
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    try:
        # Get user details from database
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        
        if not user:
            session.clear()
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            # Handle form submission
            data = request.form.to_dict()
            update_data = {}
            
            # Update fields if they exist in the form
            fields = ['firstName', 'lastName', 'phone', 'address', 'city', 'state', 'pincode', 'organization']
            for field in fields:
                if field in data:
                    update_data[field] = data[field].strip() if data[field] else ''

            # Handle file upload if present
            if 'profile-document' in request.files:
                file = request.files['profile-document']
                if file and file.filename:  # Check if file was actually selected
                    if allowed_file(file.filename):
                        try:
                            filename = secure_filename(file.filename)
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            file.save(file_path)
                            update_data['profile_document'] = filename
                            update_data['profile_image'] = os.path.join('uploads', filename)
                            update_data['profile_document_size'] = get_file_size_str(file_path)
                        except Exception as e:
                            flash(f'Error uploading file: {str(e)}', 'error')
                    else:
                        flash('Invalid file type. Allowed types are: ' + ', '.join(ALLOWED_EXTENSIONS), 'error')

            # Update user in database if there are changes
            if update_data:
                try:
                    result = user_collection.update_one(
                        {'_id': ObjectId(session['user_id'])},
                        {'$set': update_data}
                    )
                    if result.modified_count > 0:
                        flash('Profile updated successfully!', 'success')
                        # Refresh user data after update
                        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
                    else:
                        flash('No changes were made', 'info')
                except Exception as e:
                    flash(f'Error updating profile: {str(e)}', 'error')
            
            return redirect(url_for('profile'))

        # For GET request, render the profile page
        # Convert ObjectId to string for template
        user['_id'] = str(user['_id'])
        
        # Format dates if they exist
        if 'created_at' in user:
            try:
                user['created_at'] = datetime.strptime(user['created_at'], '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y')
            except:
                pass

        return render_template('profile.html', 
                            user=user,
                            profile_image=user.get('profile_image', 'img/default_profile.png'))

    except Exception as e:
        print(f"Profile error: {str(e)}")  # Add logging
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login'))
@app.route('/track_my_complaints')
def track_my_complaints():
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            flash('Please login to track your complaints')
            return redirect(url_for('login'))
        
        user_id = session['user_id']
        user = user_collection.find_one({'_id': ObjectId(user_id)})
            
        if not user:
            flash('User not found')
            return redirect(url_for('login'))
        
        # Get all complaints for this user's email
        complaints = list(complaint_collection.find({
            'email': user['email']
        }).sort('registered_at', -1))  # Sort by registration date, newest first
        
        # Format the complaints for display
        formatted_complaints = []
        for complaint in complaints:
            if complaint:  # Check if complaint exists
                try:
                    formatted_complaint = {
                        '_id': str(complaint['_id']),
                        'name': complaint.get('name', 'No Name'),
                        'email': complaint.get('email', ''),
                        'status': complaint.get('status', 'Registered'),
                        'registered_at': complaint.get('registered_at', ''),
                        'submission': complaint.get('submission', {})
                    }

                    # Add resolved info if available
                    if complaint.get('resolved_at'):
                        formatted_complaint['resolved_at'] = complaint['resolved_at']

                    formatted_complaints.append(formatted_complaint)
                except Exception as e:
                    print(f"Error formatting complaint: {str(e)}")
                    continue

        return render_template('my_complaints.html',
                            complaints=formatted_complaints,
                            user=user,
                            user_name=session.get('name', 'User'))

    except Exception as e:
        print(f"Error in track_my_complaints: {str(e)}")
        flash('An error occurred while fetching your complaints')
        return render_template('my_complaints.html',
                            complaints=[],
                            error="Failed to load complaints. Please try again.")

@app.route('/view_complaint/<complaint_id>')
def view_complaint(complaint_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Get the complaint details
        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            flash('Complaint not found')
            return redirect(url_for('track_my_complaints'))
        
        # Verify that this complaint belongs to the logged-in user
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if user['email'] != complaint['email']:
            flash('Unauthorized access')
            return redirect(url_for('track_my_complaints'))
        
        return render_template('trackcomplaint.html', complaint=complaint)
    
    except Exception as e:
        flash('Error accessing complaint details')
        return redirect(url_for('track_my_complaints'))

# Nodal Officer Registration and Login
@app.route('/nodal_registration', methods=['GET', 'POST'])
def nodal_registration():
    if request.method == 'POST':
        try:
            # Get form data
            nodal_data = {
                'name': request.form.get('name'),
                'email': request.form.get('email'),
                'organization': request.form.get('organization'),
                'designation': request.form.get('designation'),
                'phone': request.form.get('phone'),
                'password': generate_password_hash(request.form.get('password')),  # Hash the password
                'role': 'nodal_officer',
                'status': 'pending',  # Requires admin approval
                'created_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
                'last_login': None,
                'approved_by': None,
                'approved_at': None
            }
            
            # Validate required fields
            required_fields = ['name', 'email', 'organization', 'designation', 'phone', 'password']
            for field in required_fields:
                if not nodal_data[field]:
                    flash(f'{field.title()} is required')
                    return redirect(url_for('nodal_registration'))

            # Validate email format
            if not is_valid_email(nodal_data['email']):
                flash('Please enter a valid email address')
                return redirect(url_for('nodal_registration'))
            
            # Check if email already exists
            if nodal_collection.find_one({'email': nodal_data['email']}):
                flash('Email already registered')
                return redirect(url_for('nodal_registration'))
            
            # Insert into database
            result = nodal_collection.insert_one(nodal_data)
            
            if result.inserted_id:
                # Send email notification to admin
                try:
                    msg = Message('New Nodal Officer Registration',
                                sender=app.config['MAIL_USERNAME'],
                                recipients=['admin@example.com'])  # Replace with admin email
                    msg.body = f"""
                    New nodal officer registration:
                    Name: {nodal_data['name']}
                    Email: {nodal_data['email']}
                    Organization: {nodal_data['organization']}
                    Designation: {nodal_data['designation']}
                    Phone: {nodal_data['phone']}
                    """
                    mail.send(msg)
                except Exception as e:
                    print(f"Error sending email: {str(e)}")

                flash('Registration successful! Please wait for admin approval.')
                return redirect(url_for('nodal_login'))
            else:
                flash('Registration failed. Please try again.')
                
        except Exception as e:
            flash(f'Registration failed: {str(e)}')
            return redirect(url_for('nodal_registration'))
    
    return render_template('nodal_registration.html')

@app.route('/nodal_login', methods=['GET', 'POST'])
def nodal_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find the nodal officer
        nodal_officer = nodal_collection.find_one({
            'email': email,
            'password': password  # In production, verify hashed password
        })
        
        if nodal_officer:
            if nodal_officer['status'] != 'approved':
                flash('Your account is pending approval')
                return redirect(url_for('nodal_login'))
            
            # Update last login time
            nodal_collection.update_one(
                {'_id': nodal_officer['_id']},
                {'$set': {'last_login': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")}}
            )
            
            # Set all required session variables
            session['nodal_id'] = str(nodal_officer['_id'])
            session['nodal_email'] = nodal_officer['email']
            session['role'] = 'nodal_officer'
            session['name'] = nodal_officer['name']
            session['nodal_organization'] = nodal_officer['organization']  # Add organization to session
            return redirect(url_for('nodal_dashboard'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('nodal_login'))
    
    return render_template('nodal_login.html')

@app.route('/nodal_logout')
def nodal_logout():
    session.pop('nodal_id', None)
    session.pop('nodal_email', None)
    session.pop('role', None)
    session.pop('name', None)
    return redirect(url_for('nodal_login'))

@app.route('/nodal_dashboard')
def nodal_dashboard():
    if 'nodal_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('nodal_login'))

    try:
        nodal_officer = nodal_collection.find_one({'email': session['nodal_email']})
        if not nodal_officer:
            session.clear()
            flash('Officer not found', 'error')
            return redirect(url_for('nodal_login'))

        # Get complaints for the officer's organization
        complaints = list(complaint_collection.find({
            'details.organization': nodal_officer['organization']
        }).sort('registered_at', -1))

        # Format complaints data
        formatted_complaints = []
        for complaint in complaints:
            formatted_complaint = {
                'id': str(complaint['_id']),
                'name': complaint.get('name', 'Anonymous'),
                'email': complaint.get('email', ''),
                'status': complaint.get('status', 'Submitted'),
                'registered_at': complaint.get('registered_at', ''),
                'details': complaint.get('details', {}),
                'assigned_to': complaint.get('assigned_to', None),
                'assigned_to_name': complaint.get('assigned_to_name', None),
                'submission': complaint.get('submission', {})
            }
            formatted_complaints.append(formatted_complaint)

        # Calculate analytics data
        analytics = {
            'monthly_trends': calculate_monthly_trends(complaints),
            'total_cases': len(complaints),
            'resolved_cases': sum(1 for c in complaints if c.get('status', '').lower() == 'resolved'),
            'pending_cases': sum(1 for c in complaints if c.get('status', '').lower() != 'resolved')
        }

        return render_template('nodal_dashboard.html',
            nodal_officer=nodal_officer,
            complaints=formatted_complaints,
            analytics=analytics)

    except Exception as e:
        print(f"Dashboard Error: {str(e)}")
        flash('An error occurred while loading the dashboard', 'error')
        return redirect(url_for('nodal_login'))

def calculate_monthly_trends(complaints):
    try:
        # Initialize monthly trends data
        monthly_data = {}
        
        # Get last 6 months
        today = datetime.now()
        for i in range(5, -1, -1):
            month_date = today - timedelta(days=30*i)
            month_key = month_date.strftime('%B %Y')
            monthly_data[month_key] = {'total': 0, 'resolved': 0}

        # Process complaints
        for complaint in complaints:
            try:
                date_str = complaint.get('registered_at', '')
                if date_str:
                    date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                    month_key = date.strftime('%B %Y')
                    
                    if month_key in monthly_data:
                        monthly_data[month_key]['total'] += 1
                        if complaint.get('status', '').lower() == 'resolved':
                            monthly_data[month_key]['resolved'] += 1
            except Exception as e:
                print(f"Error processing complaint for trends: {str(e)}")
                continue
        
        return monthly_data

    except Exception as e:
        print(f"Error calculating trends: {str(e)}")
        return {}

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('CSRF token validation failed. Please try again.')
    return redirect(url_for('nodal_registration'))

##################################################################################################################
@app.route('/approve_nodal/<nodal_id>', methods=['POST'])
def approve_nodal(nodal_id):
    try:
        # Get current time in IST
        approval_time = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        
        # Update the nodal officer document
        result = nodal_collection.update_one(
            {'_id': ObjectId(nodal_id)},
            {'$set': {
                'status': 'approved',
                'approved_at': approval_time,
                'approved_by': session.get('admin_email', 'admin')
            }}
        )
        
        if result.modified_count:
            # Verify the update
            nodal = nodal_collection.find_one({'_id': ObjectId(nodal_id)})
            if nodal:
                try:
                    # Send approval email
                    msg = Message(
                        'Nodal Officer Application Approved',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[nodal['email']]
                    )
                    msg.body = f"""
                    Dear {nodal['name']},
                    
                    Your application to be a nodal officer has been approved on {approval_time}.
                    You can now login to your account using your registered email and password.
                
                    Best regards,
                    Admin Team
                    """
                    mail.send(msg)
                except Exception as mail_error:
                    print(f"Error sending approval email: {str(mail_error)}")

                return jsonify({
                    'success': True,
                    'approved_at': approval_time,
                    'message': 'Nodal officer approved successfully'
                })

        return jsonify({'success': False, 'message': 'Officer not found'})
    except Exception as e:
        print(f"Error in approve_nodal: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

##################################################################################################################
@app.route('/reject_nodal/<nodal_id>', methods=['POST'])
def reject_nodal(nodal_id):
    try:
        result = nodal_collection.update_one(
            {'_id': ObjectId(nodal_id)},
            {'$set': {
                'status': 'rejected',
                'rejected_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
            }}
        )
        
        if result.modified_count:
            # Send rejection email
            nodal = nodal_collection.find_one({'_id': ObjectId(nodal_id)})
            if nodal:
                msg = Message(
                    'Nodal Officer Application Status',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[nodal['email']]
                )
                msg.body = f"""
                Dear {nodal['name']},
                
                We regret to inform you that your application to be a nodal officer has been rejected.
                
                Best regards,
                Admin Team
                """
                mail.send(msg)
            
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Officer not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/nodal_details/<nodal_id>')
def nodal_details(nodal_id):
    try:
        nodal = nodal_collection.find_one({'_id': ObjectId(nodal_id)})
        if not nodal:
            flash('Nodal officer not found')
            return redirect(url_for('dashboard'))
        return render_template('nodal_details.html', nodal=nodal)
    except Exception as e:
        flash('Error accessing nodal officer details')
        return redirect(url_for('dashboard'))

##################################################################################################################
# Add these functions before the get_analytics_data route

def calculate_response_time(complaints, period=None):
    """Calculate average response time for complaints"""
    if not complaints:
        return 0
    
    total_time = 0
    count = 0
    
    for complaint in complaints:
        if 'submitted_at' in complaint and 'first_response_at' in complaint:
            try:
                submitted = datetime.strptime(complaint['submitted_at'], '%Y-%m-%d %H:%M:%S')
                responded = datetime.strptime(complaint['first_response_at'], '%Y-%m-%d %H:%M:%S')
                response_time = (responded - submitted).total_seconds() / 3600  # Convert to hours
                total_time += response_time
                count += 1
            except (ValueError, TypeError):
                continue
    
    return (total_time / count) if count > 0 else 0

def calculate_resolution_rate(complaints):
    """Calculate percentage of resolved complaints"""
    if not complaints:
        return 0
    
    resolved = sum(1 for c in complaints if c.get('status', '').lower() == 'resolved')
    return (resolved / len(complaints)) * 100

def calculate_satisfaction_rate(complaints):
    """Calculate average satisfaction rate from feedback"""
    if not complaints:
        return 0
    
    total_rating = 0
    count = 0
    
    for complaint in complaints:
        if 'feedback' in complaint and 'rating' in complaint['feedback']:
            try:
                rating = int(complaint['feedback']['rating'])
                total_rating += rating
                count += 1
            except (ValueError, TypeError):
                continue
    
    return (total_rating / count) if count > 0 else 0

def calculate_feedback_rate(complaints):
    """Calculate percentage of complaints with feedback"""
    if not complaints:
        return 0
    
    feedback_count = sum(1 for c in complaints if 'feedback' in c and c['feedback'])
    return (feedback_count / len(complaints)) * 100

def calculate_followup_rate(complaints):
    """Calculate percentage of complaints requiring followup"""
    if not complaints:
        return 0
    
    followup_count = sum(1 for c in complaints if c.get('followups', []))
    return (followup_count / len(complaints)) * 100

def calculate_escalation_rate(complaints):
    """Calculate percentage of complaints that were escalated"""
    if not complaints:
        return 0
    
    escalated = sum(1 for c in complaints if c.get('escalated', False))
    return (escalated / len(complaints)) * 100

# Previous month calculation functions
def calculate_previous_response_time(complaints):
    """Calculate response time for previous month"""
    last_month = datetime.now() - timedelta(days=30)
    previous_complaints = [c for c in complaints if datetime.strptime(c['submitted_at'], '%Y-%m-%d %H:%M:%S') < last_month]
    return calculate_response_time(previous_complaints)

def calculate_previous_resolution_rate(complaints):
    """Calculate resolution rate for previous month"""
    last_month = datetime.now() - timedelta(days=30)
    previous_complaints = [c for c in complaints if datetime.strptime(c['submitted_at'], '%Y-%m-%d %H:%M:%S') < last_month]
    return calculate_resolution_rate(previous_complaints)

def calculate_previous_satisfaction_rate(complaints):
    """Calculate satisfaction rate for previous month"""
    last_month = datetime.now() - timedelta(days=30)
    previous_complaints = [c for c in complaints if datetime.strptime(c['submitted_at'], '%Y-%m-%d %H:%M:%S') < last_month]
    return calculate_satisfaction_rate(previous_complaints)

def calculate_previous_feedback_rate(complaints):
    """Calculate feedback rate for previous month"""
    last_month = datetime.now() - timedelta(days=30)
    previous_complaints = [c for c in complaints if datetime.strptime(c['submitted_at'], '%Y-%m-%d %H:%M:%S') < last_month]
    return calculate_feedback_rate(previous_complaints)

def calculate_previous_followup_rate(complaints):
    """Calculate followup rate for previous month"""
    last_month = datetime.now() - timedelta(days=30)
    previous_complaints = [c for c in complaints if datetime.strptime(c['submitted_at'], '%Y-%m-%d %H:%M:%S') < last_month]
    return calculate_followup_rate(previous_complaints)

def calculate_previous_escalation_rate(complaints):
    """Calculate escalation rate for previous month"""
    last_month = datetime.now() - timedelta(days=30)
    previous_complaints = [c for c in complaints if datetime.strptime(c['submitted_at'], '%Y-%m-%d %H:%M:%S') < last_month]
    return calculate_escalation_rate(previous_complaints)

##################################################################################################################
@app.route('/nodal_view_complaint/<complaint_id>')
def nodal_view_complaint(complaint_id):
    if 'nodal_id' not in session and 'nodal_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('nodal_login'))

    try:
        # Get the complaint details
        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            flash('Complaint not found', 'error')
            return redirect(url_for('nodal_dashboard'))

        # Format the complaint data
        complaint['id'] = str(complaint['_id'])
        if 'registered_at' in complaint:
            try:
                date_obj = datetime.strptime(complaint['registered_at'], '%Y-%m-%d %H:%M:%S')
                complaint['registered_at'] = date_obj.strftime('%B %d, %Y %I:%M %p')
            except:
                complaint['registered_at'] = 'Date not available'
        
        if 'resolved_at' in complaint:
            try:
                date_obj = datetime.strptime(complaint['resolved_at'], '%Y-%m-%d %H:%M:%S')
                complaint['resolved_at'] = date_obj.strftime('%B %d, %Y %I:%M %p')
            except:
                complaint['resolved_at'] = 'Date not available'
        
        return render_template('nodal_view_complaint.html', complaint=complaint)

    except Exception as e:
        print(f"Error in nodal_view_complaint: {str(e)}")
        flash('An error occurred while loading the complaint', 'error')
        return redirect(url_for('nodal_dashboard'))
    

    
@app.route('/resolve_complaint/<complaint_id>', methods=['POST'])
def resolve_complaint(complaint_id):
    try:
        # Get current time in IST
        resolution_time = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        
        # Update the complaint document in MongoDB
        result = complaint_collection.update_one(
            {'_id': ObjectId(complaint_id)},
            {'$set': {
                'status': 'resolved',
                'resolved_at': resolution_time
            }}
        )

        if result.modified_count:
            # Fetch complaint details
            complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
            if complaint:
                try:
                    # Send resolution email
                    msg = Message(
                        'Your Complaint Has Been Resolved',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[complaint['email']]
                    )
                    msg.body = f"""
                    Dear {complaint['name']},
                    
                    Your complaint (ID: {complaint_id}) 
                    has been successfully resolved on {resolution_time}.
                    
                    If you have any further issues, please do not hesitate 
                    to reach out.

                    Best regards,
                    Support Team
                    """
                    mail.send(msg)
                except Exception as mail_error:
                    print(f"Error sending resolution email: {str(mail_error)}")

                return jsonify({
                    'success': True,
                    'resolved_at': resolution_time,
                    'message': 'Complaint resolved successfully'
                })

        return jsonify({'success': False, 'message': 'Complaint not found'})
    except Exception as e:
        print(f"Error in resolve_complaint: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_complaint/<complaint_id>', methods=['POST'])
def update_complaint(complaint_id):
    if 'nodal_id' not in session and 'nodal_email' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})

    try:
        # Get update data
        data = request.get_json()
        status = data.get('status')
        notes = data.get('notes')
        
        # Prepare update data
        update_data = {'$set': {}}
        
        if status:
            update_data['$set']['status'] = status
            if status.lower() == 'resolved':  # Case-insensitive comparison
                # Check if this is an admin or nodal officer
                if session.get('admin'):
                    # For admin resolution
                    admin_email = session.get('admin_email', 'admin123@gmail.com')
                    admin_name = session.get('admin_name', 'System Administrator')
                    
                    update_data.update({
                        'resolved_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
                        'resolved_by': admin_email,
                        'resolved_by_name': admin_name,
                        'resolved_by_organization': 'System Administration'
                    })
                else:
                    # For nodal officer resolution
                    resolver_name = session.get('name')
                    resolver_email = session.get('nodal_email')
                    resolver_org = session.get('nodal_organization')
                    
                    if not all([resolver_name, resolver_email, resolver_org]):
                        return jsonify({'success': False, 'error': 'Resolver information not found. Please login again.'})
                    
                    update_data.update({
                        'resolved_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
                        'resolved_by': resolver_email,
                        'resolved_by_name': resolver_name,
                        'resolved_by_organization': resolver_org
                    })
        
        if notes:
            update_data['$push'] = {
                'notes': {
                    'text': notes,
                    'added_by': session.get('nodal_email'),
                    'added_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
                }
            }

        # Update the complaint
        result = complaint_collection.update_one(
            {'_id': ObjectId(complaint_id)},
            update_data
        )

        if result.modified_count:
            # Get updated complaint for response
            updated_complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
            return jsonify({
                'success': True,
                'message': 'Complaint updated successfully',
                'complaint': {
                    'id': str(updated_complaint['_id']),
                    'status': updated_complaint.get('status', 'pending'),
                    'resolved_at': updated_complaint.get('resolved_at'),
                    'notes': updated_complaint.get('notes', [])
                }
            })
        
        return jsonify({
            'success': False,
            'message': 'Complaint not found or no changes made'
        })

    except Exception as e:
        print(f"Error updating complaint: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while updating the complaint'
        })
###################### admin dash #############################################
@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Check credentials
            if email == 'admin12@gmail.com' and password == 'admin@123':
                session['admin'] = True
                session['admin_email'] = email
                session['admin_name'] = 'System Administrator'  # Add admin name
                session['role'] = 'admin'  # Add admin role
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error')
                return redirect(url_for('adminlogin'))
                             
        except Exception as e:
            print(f"Admin login error: {str(e)}")
            flash('Login failed', 'error')
            return redirect(url_for('adminlogin'))

    return render_template('adminlogin.html')

@app.route('/dashboard')
@app.route('/dashboard/<status>')
def dashboard(status=None):
    if not session.get('admin'):
        flash('Please login first', 'error')
        return redirect(url_for('adminlogin'))

    try:
        # Initialize default values
        stats = {
            'total_complaints': 0,
            'total_resolved': 0,
            'total_pending': 0,
            'pending_complaints': 0,
            'total_officers': 0,
            'approved_officers': 0,
            'pending_officers': 0,
            'resolution_rate': 0,
            'avg_response_time': 0,
            'satisfaction_rate': 0,
            'monthly_trends': {
                'labels': [],
                'total': [],
                'resolved': [],
                'pending': []
            },
            'nodal_stats': {
                'total': 0,
                'approved': 0,
                'pending': 0
            }
        }

        # Get basic statistics with safe defaults
        total_cases = complaint_collection.count_documents({}) or 0
        total_resolved = complaint_collection.count_documents({
            'status': {'$regex': '^resolved$', '$options': 'i'}
        }) or 0
        total_pending = complaint_collection.count_documents({
            'status': {'$regex': '^submitted$', '$options': 'i'}
        }) or 0

        # Get complaints based on status
        query = {}
        if status:
            if status.lower() == 'resolved':
                query = {'status': {'$regex': '^resolved$', '$options': 'i'}}
            elif status.lower() == 'pending':
                query = {'status': {'$regex': '^submitted$', '$options': 'i'}}

        # Get filtered complaints with safe list conversion
        all_complaints = list(complaint_collection.find(query).sort('registered_at', -1)) or []
        
        # Format dates and ObjectIds for template
        formatted_complaints = []
        for complaint in all_complaints:
            try:
                formatted_complaint = {
                    '_id': str(complaint['_id']),
                    'name': complaint.get('name', 'No Name'),
                    'email': complaint.get('email', ''),
                    'details': complaint.get('details', {}),
                    'status': complaint.get('status', 'Unknown').capitalize(),
                    'registered_at': complaint.get('registered_at', ''),
                    'resolved_by': complaint.get('resolved_by', ''),
                    'resolved_by_name': complaint.get('resolved_by_name', ''),
                    'resolved_at': complaint.get('resolved_at', ''),
                    'resolved_by_organization': complaint.get('resolved_by_organization', '')
                }
                
                if formatted_complaint['registered_at']:
                    try:
                        date_obj = datetime.strptime(formatted_complaint['registered_at'], '%Y-%m-%d %H:%M:%S')
                        formatted_complaint['registered_at'] = date_obj.strftime('%B %d, %Y %I:%M %p')
                    except (ValueError, TypeError):
                        formatted_complaint['registered_at'] = 'Date unknown'
                
                if formatted_complaint['resolved_at']:
                    try:
                        date_obj = datetime.strptime(formatted_complaint['resolved_at'], '%Y-%m-%d %H:%M:%S')
                        formatted_complaint['resolved_at'] = date_obj.strftime('%B %d, %Y %I:%M %p')
                    except (ValueError, TypeError):
                        formatted_complaint['resolved_at'] = 'Date unknown'
                
                formatted_complaints.append(formatted_complaint)
            except Exception as e:
                print(f"Error formatting complaint: {str(e)}")
                continue

        # Get nodal officer data
        pending_officers = list(nodal_collection.find({'status': 'pending'}).sort('applied_date', -1))
        approved_officers = list(nodal_collection.find({'status': 'approved'}).sort('approved_at', -1))
        rejected_officers = list(nodal_collection.find({'status': 'rejected'}).sort('rejection_date', -1))

        # Format dates for nodal officers
        for officer in approved_officers:
            if 'approved_at' in officer:
                try:
                    date_obj = datetime.strptime(officer['approved_at'], '%Y-%m-%d %H:%M:%S')
                    officer['formatted_approved_at'] = date_obj.strftime('%B %d, %Y %I:%M %p')
                except:
                    officer['formatted_approved_at'] = 'Date unknown'

        # Calculate organization statistics
        org_stats = []
        organizations = nodal_collection.distinct('organization')
        for org in organizations:
            org_stat = {
                '_id': org,
                'approved': nodal_collection.count_documents({'organization': org, 'status': 'approved'}),
                'pending': nodal_collection.count_documents({'organization': org, 'status': 'pending'})
            }
            org_stats.append(org_stat)

        # Update stats with actual values
        stats.update({
            'total_complaints': total_cases,
            'total_resolved': total_resolved,
            'total_pending': total_pending,
            'pending_complaints': total_pending,
            'resolution_rate': round((total_resolved / total_cases * 100) if total_cases > 0 else 0, 2),
            'avg_response_time': calculate_response_time(formatted_complaints),
            'satisfaction_rate': calculate_satisfaction_rate(formatted_complaints)
        })

        return render_template('admindash.html',
            total_cases=total_cases,
            total_resolved=total_resolved,
            total_pending=total_pending,
            all_complaints=formatted_complaints,
            stats=stats,
            current_status=status or 'all',
            org_stats=org_stats,
            pending_officers=pending_officers,
            approved_officers=approved_officers,
            rejected_officers=rejected_officers)
            
    except Exception as e:
        print(f"Dashboard Error: {str(e)}")
        return render_template('admindash.html',
            total_cases=0,
            total_resolved=0,
            total_pending=0,
            all_complaints=[],
            stats={
                'total_complaints': 0,
                'total_resolved': 0,
                'total_pending': 0,
                'resolution_rate': 0
            },
            current_status='all',
            org_stats=[],
            pending_officers=[],
            approved_officers=[],
            rejected_officers=[],
            error=str(e))

def calculate_analytics_data():
    try:
        # Get basic statistics
        total_cases = complaint_collection.count_documents({}) or 0
        total_resolved = complaint_collection.count_documents({
            'status': {'$regex': '^resolved$', '$options': 'i'}
        }) or 0
        total_pending = complaint_collection.count_documents({
            'status': {'$not': {'$regex': '^resolved$', '$options': 'i'}}
        }) or 0
        
        # Get monthly trends data
        trends_data = {
            'labels': [],
            'total': [],
            'resolved': [],
            'pending': []
        }
        
        try:
            # Get complaints from the last 6 months
            six_months_ago = datetime.now() - timedelta(days=180)
            complaints = list(complaint_collection.find({
                'registered_at': {'$gte': six_months_ago.strftime('%Y-%m-%d %H:%M:%S')}
            }))
            
            # Group by month
            monthly_data = {}
            for complaint in complaints:
                try:
                    date = datetime.strptime(complaint['registered_at'], '%Y-%m-%d %H:%M:%S')
                    month_key = date.strftime('%B %Y')
                    
                    if month_key not in monthly_data:
                        monthly_data[month_key] = {
                            'total': 0,
                            'resolved': 0,
                            'pending': 0
                        }
                    
                    monthly_data[month_key]['total'] += 1
                    if complaint.get('status', '').lower() == 'resolved':
                        monthly_data[month_key]['resolved'] += 1
                    else:
                        monthly_data[month_key]['pending'] += 1
                except Exception as e:
                    print(f"Error processing complaint for trends: {str(e)}")
                    continue
            
            # Sort months chronologically
            sorted_months = sorted(monthly_data.keys(), 
                key=lambda x: datetime.strptime(x, '%B %Y'))
            
            # Populate trends data
            trends_data['labels'] = sorted_months
            trends_data['total'] = [monthly_data[month]['total'] for month in sorted_months]
            trends_data['resolved'] = [monthly_data[month]['resolved'] for month in sorted_months]
            trends_data['pending'] = [monthly_data[month]['pending'] for month in sorted_months]
            
        except Exception as e:
            print(f"Error calculating trends: {str(e)}")
            # Return empty trends data on error
            trends_data = {
                'labels': ['No Data'],
                'total': [0],
                'resolved': [0],
                'pending': [0]
            }
        
        # Calculate resolution rate with error handling
        resolution_rate = (total_resolved / total_cases * 100) if total_cases > 0 else 0
        
        # Get nodal officer stats
        nodal_stats = {
            'total': nodal_collection.count_documents({}) or 0,
            'approved': nodal_collection.count_documents({'status': 'approved'}) or 0,
            'pending': nodal_collection.count_documents({'status': 'pending'}) or 0
        }
        
        return {
            'total_cases': total_cases,
            'total_resolved': total_resolved,
            'total_pending': total_pending,
            'resolution_rate': round(resolution_rate, 2),
            'monthly_trends': trends_data,
            'nodal_stats': nodal_stats,
            'stats': {  # Add stats for dashboard
                'total_complaints': total_cases,
                'total_resolved': total_resolved,
                'total_pending': total_pending,
                'total_officers': nodal_stats['total'],
                'approved_officers': nodal_stats['approved'],
                'pending_officers': nodal_stats['pending'],
                'pending_complaints': total_pending,
                'avg_response_time': 0,  # Default value
                'satisfaction_rate': 0  # Default value
            }
        }
    except Exception as e:
        print(f"Error calculating analytics: {str(e)}")
        return {
            'total_cases': 0,
            'total_resolved': 0,
            'total_pending': 0,
            'resolution_rate': 0,
            'monthly_trends': {
                'labels': ['No Data'],
                'total': [0],
                'resolved': [0],
                'pending': [0]
            },
            'nodal_stats': {
                'total': 0,
                'approved': 0,
                'pending': 0
            },
            'stats': {
                'total_complaints': 0,
                'total_resolved': 0,
                'total_pending': 0,
                'total_officers': 0,
                'approved_officers': 0,
                'pending_officers': 0,
                'pending_complaints': 0,
                'avg_response_time': 0,
                'satisfaction_rate': 0
            }
        }

@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('adminlogin'))

def is_logged_in():
    return 'user_id' in session

@app.route('/get_analytics_data')
def get_analytics_data():
    try:
        # Initialize default values
        stats = {
            'total_cases': 0,
            'total_resolved': 0,
            'total_pending': 0,
            'nodal_stats': {'approved': 0, 'pending': 0},
            'org_stats': {
                'labels': ['No Data'],
                'values': [0]
            },
            'monthly_trends': {
                'labels': [datetime.now().strftime('%m/%Y')],
                'total': [0],
                'resolved': [0],
                'pending': [0]
            },
            'case_stats': {
                'current': [0, 0, 0, 0, 0, 0],
                'previous': [0, 0, 0, 0, 0, 0]
            }
        }

        # Get basic statistics
        stats['total_cases'] = complaint_collection.count_documents({}) or 0
        stats['total_resolved'] = complaint_collection.count_documents({
            'status': {'$regex': '^resolved$', '$options': 'i'}
        }) or 0
        stats['total_pending'] = complaint_collection.count_documents({
            'status': {'$not': {'$regex': '^resolved$', '$options': 'i'}}
        }) or 0

        # Get nodal officer counts
        stats['nodal_stats']['approved'] = nodal_collection.count_documents({'status': 'approved'}) or 0
        stats['nodal_stats']['pending'] = nodal_collection.count_documents({'status': 'pending'}) or 0

        # Get organization statistics
        org_pipeline = [
            {'$group': {'_id': '$organization', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 6}
        ]
        org_stats = list(nodal_collection.aggregate(org_pipeline))

        # Format organization stats
        stats['org_stats']['labels'] = [str(stat['_id']) if stat['_id'] else 'Unknown' for stat in org_stats]
        stats['org_stats']['values'] = [int(stat['count']) for stat in org_stats]

        # Generate monthly trends data
        current_date = datetime.now()
        for i in range(5, -1, -1):
            month_date = current_date - timedelta(days=30*i)
            month_str = month_date.strftime('%m/%Y')
            stats['monthly_trends']['labels'].append(month_str)
            stats['monthly_trends']['total'].append(0)
            stats['monthly_trends']['resolved'].append(0)
            stats['monthly_trends']['pending'].append(0)

        # Get all complaints for calculations
        complaints = list(complaint_collection.find())

        # Calculate case statistics
        if complaints:
            stats['case_stats']['current'] = [
                round(calculate_response_time(complaints) or 0),
                round(calculate_resolution_rate(complaints) or 0),
                round(calculate_satisfaction_rate(complaints) or 0),
                round(calculate_feedback_rate(complaints) or 0),
                round(calculate_followup_rate(complaints) or 0),
                round(calculate_escalation_rate(complaints) or 0)
            ]
            stats['case_stats']['previous'] = [
                round(calculate_previous_response_time(complaints) or 0),
                round(calculate_previous_resolution_rate(complaints) or 0),
                round(calculate_previous_satisfaction_rate(complaints) or 0),
                round(calculate_previous_feedback_rate(complaints) or 0),
                round(calculate_previous_followup_rate(complaints) or 0),
                round(calculate_previous_escalation_rate(complaints) or 0)
            ]

        return jsonify(stats)

    except Exception as e:
        print(f"Analytics Error: {str(e)}")
        # Return default values in case of error
        return jsonify({
            'total_cases': 0,
            'total_resolved': 0,
            'total_pending': 0,
            'nodal_stats': {'approved': 0, 'pending': 0},
            'org_stats': {
                'labels': ['No Data'],
                'values': [0]
            },
            'monthly_trends': {
                'labels': [datetime.now().strftime('%m/%Y')],
                'total': [0],
                'resolved': [0],
                'pending': [0]
            },
            'case_stats': {
                'current': [0, 0, 0, 0, 0, 0],
                'previous': [0, 0, 0, 0, 0, 0]
            }
        })

@app.route('/update_status/<complaint_id>', methods=['POST'])
def update_status(complaint_id):
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not ObjectId.is_valid(complaint_id):
            return jsonify({'success': False, 'error': 'Invalid complaint ID'})
            
        # Find the complaint
        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            return jsonify({'success': False, 'error': 'Complaint not found'})

        # Update the complaint status
        update_data = {
            'status': new_status,
            'updated_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if new_status.lower() == 'resolved':  # Case-insensitive comparison
            # Check if this is an admin or nodal officer
            if session.get('admin'):
                # For admin resolution
                admin_email = session.get('admin_email', 'admin123@gmail.com')
                admin_name = session.get('admin_name', 'System Administrator')
                
                update_data.update({
                    'resolved_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
                    'resolved_by': admin_email,
                    'resolved_by_name': admin_name,
                    'resolved_by_organization': 'System Administration'
                })
            else:
                # For nodal officer resolution
                resolver_name = session.get('name')
                resolver_email = session.get('nodal_email')
                resolver_org = session.get('nodal_organization')
                
                if not all([resolver_name, resolver_email, resolver_org]):
                    return jsonify({'success': False, 'error': 'Resolver information not found. Please login again.'})
                
                update_data.update({
                    'resolved_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
                    'resolved_by': resolver_email,
                    'resolved_by_name': resolver_name,
                    'resolved_by_organization': resolver_org
                })
        
        result = complaint_collection.update_one(
            {'_id': ObjectId(complaint_id)},
            {'$set': update_data}
        )

        if result.modified_count:
            # Get updated counts
            all_complaints = list(complaint_collection.find())
            total_complaints = len(all_complaints)
            total_resolved = sum(1 for c in all_complaints if c.get('status', '').lower() == 'resolved')
            total_pending = total_complaints - total_resolved

            # Send email for resolved complaints
            if new_status.lower() == 'resolved' and complaint.get('email'):
                try:
                    send_resolution_email(complaint['email'], complaint)
                except Exception as e:
                    print(f"Error sending email: {str(e)}")

            return jsonify({
                'success': True,
                'total_resolved': total_resolved,
                'total_pending': total_pending,
                'new_status': new_status
            })

        return jsonify({'success': False, 'message': 'Failed to update status'})

    except Exception as e:
        print(f"Error updating status: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

##############################  Resolve mail sending #####################################################################################
def send_resolution_email(email, complaint):
    """Sends an email notification when a complaint is resolved."""
    try:
        subject = "Your Complaint Has Been Resolved - Raise My Voice"
        body = f"""
        Hello {complaint.get('name')},

        Your complaint "{complaint.get('title', 'regarding Sexual Harassment')}" has been successfully resolved by:
        
        Resolver Name: {complaint.get('resolved_by_name', 'Unknown')}
        Organization: {complaint.get('resolved_by_organization', 'Unknown')}
        
        If your problem is not resolved, you can raise a new complaint and contact us.
        Thank you for reaching out to us. If you have any further concerns, feel free to contact us.

        Best Regards,
        Raise My Voice Team
        """

        msg = Message(subject, recipients=[email], body=body)
        mail.send(msg)
        print(f"Email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

@app.route('/take_case/<complaint_id>', methods=['POST'])
def take_case(complaint_id):
    try:
        if not session.get('nodal_email'):
            return jsonify({'success': False, 'message': 'Please login first'})

        if not ObjectId.is_valid(complaint_id):
            return jsonify({'success': False, 'message': 'Invalid complaint ID'})

        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            return jsonify({'success': False, 'message': 'Complaint not found'})

        # Check if complaint is already assigned
        if complaint.get('assigned_to'):
            return jsonify({'success': False, 'message': 'Case already assigned'})

        # Check if nodal officer is from the same organization
        if complaint.get('details', {}).get('organization') != session.get('nodal_organization'):
            return jsonify({'success': False, 'message': 'You can only take cases from your organization'})

        # Update complaint with assignment
        result = complaint_collection.update_one(
            {'_id': ObjectId(complaint_id)},
            {
                '$set': {
                    'assigned_to': session.get('nodal_email'),
                    'assigned_to_name': session.get('name'),
                    'assigned_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
                }
            }
        )

        if result.modified_count:
            return jsonify({'success': True, 'message': 'Case assigned successfully'})
        return jsonify({'success': False, 'message': 'Failed to assign case'})

    except Exception as e:
        print(f"Error taking case: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'})

@app.route('/send_investigation/<complaint_id>', methods=['POST'])
def send_investigation(complaint_id):
    try:
        if not session.get('nodal_email'):
            return jsonify({'success': False, 'message': 'Please login first'})

        data = request.get_json()
        message = data.get('message')

        if not message:
            return jsonify({'success': False, 'message': 'Message is required'})

        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            return jsonify({'success': False, 'message': 'Complaint not found'})

        if complaint.get('assigned_to') != session.get('nodal_email'):
            return jsonify({'success': False, 'message': 'You are not assigned to this case'})

        # Send email to complainant
        try:
            subject = "Investigation Update - Your Complaint"
            email_body = f"""
            Dear {complaint.get('name')},

            Investigation Update for your complaint:

            {message}

            Best regards,
            {session.get('name')}
            {session.get('nodal_organization')}
            """

            msg = Message(subject, recipients=[complaint.get('email')], body=email_body)
            mail.send(msg)

            # Update complaint with investigation details
            complaint_collection.update_one(
                {'_id': ObjectId(complaint_id)},
                {
                    '$push': {
                        'investigation_updates': {
                            'message': message,
                            'sent_by': session.get('nodal_email'),
                            'sent_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
                        }
                    }
                }
            )

            return jsonify({'success': True, 'message': 'Investigation details sent successfully'})

        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to send email'})

    except Exception as e:
        print(f"Error sending investigation: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'})

@app.route('/send_action_taken/<complaint_id>', methods=['POST'])
def send_action_taken(complaint_id):
    try:
        if not session.get('nodal_email'):
            return jsonify({'success': False, 'message': 'Please login first'})

        data = request.get_json()
        message = data.get('message')

        if not message:
            return jsonify({'success': False, 'message': 'Message is required'})

        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            return jsonify({'success': False, 'message': 'Complaint not found'})

        if complaint.get('assigned_to') != session.get('nodal_email'):
            return jsonify({'success': False, 'message': 'You are not assigned to this case'})

        # Send email to complainant
        try:
            subject = "Action Taken - Your Complaint"
            email_body = f"""
            Dear {complaint.get('name')},

            Action taken on your complaint:

            {message}

            Best regards,
            {session.get('name')}
            {session.get('nodal_organization')}
            """

            msg = Message(subject, recipients=[complaint.get('email')], body=email_body)
            mail.send(msg)

            # Update complaint with action taken details
            complaint_collection.update_one(
                {'_id': ObjectId(complaint_id)},
                {
                    '$push': {
                        'action_updates': {
                            'message': message,
                            'sent_by': session.get('nodal_email'),
                            'sent_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
                        }
                    }
                }
            )

            return jsonify({'success': True, 'message': 'Action taken details sent successfully'})

        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to send email'})

    except Exception as e:
        print(f"Error sending action taken: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'})

@app.route('/view_document/<filename>')
def view_document(filename):
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
        
    try:
        # Get the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            flash('Document not found', 'error')
            return redirect(url_for('profile'))
            
        # Get file extension
        file_extension = os.path.splitext(filename)[1].lower()
        
        # Set appropriate content type
        if file_extension == '.pdf':
            content_type = 'application/pdf'
        elif file_extension in ['.jpg', '.jpeg']:
            content_type = 'image/jpeg'
        elif file_extension == '.png':
            content_type = 'image/png'
        else:
            content_type = 'application/octet-stream'
            
        return send_file(file_path, mimetype=content_type)
        
    except Exception as e:
        flash(f'Error viewing document: {str(e)}', 'error')
        return redirect(url_for('profile'))

@app.route('/get_user_details')
def get_user_details():
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not logged in'}), 401
            
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        return jsonify({
            'success': True,
            'name': user.get('name', ''),
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'address': user.get('address', '')
        })
        
    except Exception as e:
        print(f"Error fetching user details: {str(e)}")
        return jsonify({'success': False, 'message': 'Error fetching user details'}), 500

@app.route('/complaint_details_form')
def complaint_details_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # Get query parameters
    name = request.args.get('name', '')
    email = request.args.get('email', '')
    phone = request.args.get('phone', '')
    address = request.args.get('address', '')
    
    return render_template('complaint/complaintdetails.html', 
                         name=name,
                         email=email,
                         phone=phone,
                         address=address)

@app.route('/api/submit_complaint', methods=['POST'])
@json_response
def api_submit_complaint():
    print("Received request:", request.method)
    print("Content-Type:", request.headers.get('Content-Type'))
    print("Is JSON?", request.is_json)
    
    # Check if user is logged in
    if 'user_id' not in session:
        return {'success': False, 'message': 'Please login first'}, 401
    
    # Check if request is JSON
    if not request.is_json:
        return {'success': False, 'message': 'Invalid content type. Expected JSON'}, 400
        
    # Get and validate data
    data = request.get_json()
    print("Received data:", data)
    
    if not data:
        return {'success': False, 'message': 'No data provided'}, 400
        
    # Validate required fields
    required_fields = ['name', 'email', 'phone', 'address', 'gender', 'age']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return {
            'success': False, 
            'message': f'Missing required fields: {", ".join(missing_fields)}'
        }, 400
        
    try:
        # Add metadata
        complaint_data = {
            'user_id': session['user_id'],
            'complaint_id': str(uuid.uuid4()),
            'status': "Registered",
            'registered_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            **data  # Include all form data
        }
        
        print("Saving complaint:", complaint_data)
        
        # Store in database
        result = complaint_collection.insert_one(complaint_data)
        
        if not result.inserted_id:
            return {'success': False, 'message': 'Failed to save complaint'}, 500
            
        response_data = {
            'success': True,
            'message': 'Complaint submitted successfully',
            'complaint_id': complaint_data['complaint_id']
        }
        print("Sending response:", response_data)
        return response_data
        
    except Exception as e:
        print(f"Error submitting complaint: {str(e)}")
        return {'success': False, 'message': str(e)}, 500

@app.route('/complaint_submit_success')
def complaint_submit_success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    try:
        # Get all complaints for the current user
        user_complaints = list(complaint_collection.find({'user_id': session['user_id']}))
        
        # Convert ObjectId to string for JSON serialization
        for complaint in user_complaints:
            complaint['_id'] = str(complaint['_id'])
            
        return render_template('complaint/submission.html', complaints=user_complaints)
        
    except Exception as e:
        print(f"Error fetching complaints: {str(e)}")
        return redirect(url_for('home'))

@app.route('/my_complaints')
def my_complaints():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        # Get all complaints for the current user
        user_complaints = list(complaint_collection.find({'user_id': session['user_id']}))
        
        # Convert ObjectId to string for JSON serialization
        for complaint in user_complaints:
            complaint['_id'] = str(complaint['_id'])
            
        return render_template('my_complaints.html', complaints=user_complaints)
        
    except Exception as e:
        print(f"Error fetching complaints: {str(e)}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
import re
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
import bcrypt
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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Changed from 5 minutes to 1 day
app.config['SESSION_PERMANENT'] = True  # Added to make sessions permanent

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
            'password': password,  # Store password as plain text
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
                    'password': data.get('password'),  # Store password as plain text
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
    return render_template('index.html')
@app.route('/index')
def index():
    return render_template('index.html')
#################################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    try:
        # Check if the request has JSON data
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Invalid request format'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        email = data.get('email')
        password = data.get('password')
        otp = data.get('otp')
        
        if not all([email, password, otp]):
            return jsonify({'success': False, 'message': 'Please enter email, password and OTP'}), 400
            
        # Verify user exists
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
        # Verify password
        if user['password'] != password:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Verify OTP
        stored_otp = otp_collection.find_one({
            'email': email,
            'purpose': 'login',
            'is_used': False,
            'expiry': {'$gt': datetime.now(pytz.timezone("Asia/Kolkata"))}
        })
        
        if not stored_otp:
            return jsonify({'success': False, 'message': 'No valid OTP found. Please request a new OTP.'}), 401
            
        if stored_otp['otp'] != otp:
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
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'name': user.get('name', ''),
            'redirect': url_for('home')
        })
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/home')
def home():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('index'))  # Changed from login to index
        
    try:
        # Get user details from database
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            session.clear()
            return redirect(url_for('index'))  # Changed from login to index
            
        return render_template('home.html', user=user)
    except Exception as e:
        print(f"Error loading home page: {str(e)}")
        session.clear()
        return redirect(url_for('index'))  # Changed from login to index

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
        print("DEBUG: No user_id in session")
        print("DEBUG: Session contents:", dict(session))
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    try:
        print(f"DEBUG: User ID in session: {session['user_id']}")
        print(f"DEBUG: Session contents: {dict(session)}")
        # Make session permanent
        session.permanent = True
        
        # Get user details from database
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        
        if not user:
            print("DEBUG: User not found in database")
            session.clear()
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        print(f"DEBUG: Found user: {user.get('email', 'No email')}")
        
        if request.method == 'POST':
            # Handle form submission
            firstName = request.form.get('firstName')
            lastName = request.form.get('lastName')
            phone = request.form.get('phone')
            address = request.form.get('address')
            city = request.form.get('city')
            state = request.form.get('state')
            pincode = request.form.get('pincode')
            organization = request.form.get('organization')
            
            # Update user data
            update_data = {
                'firstName': firstName,
                'lastName': lastName,
                'phone': phone,
                'address': address,
                'city': city,
                'state': state,
                'pincode': pincode,
                'organization': organization
            }
            
            # Handle profile picture upload
            if 'profile-document' in request.files:
                file = request.files['profile-document']
                if file and file.filename:
                    if allowed_file(file.filename):
                        try:
                            filename, file_path = save_file_with_unique_name(file)
                            update_data['profile_document'] = filename
                            update_data['profile_document_size'] = get_file_size_str(file_path)
                            
                            # If it's an image, also update the profile image
                            if file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                                update_data['profile_image'] = f'uploads/{filename}'
                        except Exception as e:
                            flash(f'Error uploading file: {str(e)}', 'error')
                    else:
                        flash('Invalid file type. Allowed types are: ' + ', '.join(ALLOWED_EXTENSIONS), 'error')

            # Update user in database
            user_collection.update_one(
                        {'_id': ObjectId(session['user_id'])},
                        {'$set': update_data}
                    )
            
            flash('Profile updated successfully', 'success')
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

        # Set default profile image if none exists
        profile_image = user.get('profile_image', 'img/default_profile.png')
        if not profile_image.startswith('uploads/'):
            profile_image = 'img/default_profile.png'

        # Ensure email is set in user data
        if 'email' not in user:
            user['email'] = session.get('email', '')
            print(f"DEBUG: Setting email from session: {user['email']}")

        return render_template('profile.html', 
                            user=user,
                            profile_image=profile_image)

    except Exception as e:
        print(f"DEBUG: Error in profile route: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('profile'))

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

@app.route('/register_complaint', methods=['GET', 'POST'])
def register_complaint():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        try:
            # Get form data
            data = request.form.to_dict()
            
            # Add complaint to database
            complaint_data = {
                'user_id': session['user_id'],
                'name': data.get('name'),
                'email': data.get('email'),
                'phone': data.get('phone'),
                'address': data.get('address'),
                'status': 'pending',
                'created_at': datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
            }
            
            result = complaint_collection.insert_one(complaint_data)
            
            if result.inserted_id:
                flash('Complaint registered successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Failed to register complaint. Please try again.', 'error')
                return redirect(url_for('home'))
                
        except Exception as e:
            print(f"Error registering complaint: {str(e)}")
            flash('An error occurred while registering the complaint.', 'error')
            return redirect(url_for('home'))
            
    return redirect(url_for('home'))

@app.route('/submit_complaint', methods=['POST'])
@csrf.exempt
def submit_complaint():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    try:
        # Get form data
        data = request.form.to_dict()
        print("Received form data:", data)  # Debug print
        
        # Handle file uploads
        evidence_file = request.files.get('evidence')
        id_proof_file = request.files.get('idProof')
        
        # Save files if provided
        evidence_path = None
        id_proof_path = None
        
        if evidence_file and allowed_file(evidence_file.filename):
            filename, file_path = save_file_with_unique_name(evidence_file)
            evidence_path = f'uploads/{filename}'
            print("Saved evidence file:", evidence_path)  # Debug print
            
        if id_proof_file and allowed_file(id_proof_file.filename):
            filename, file_path = save_file_with_unique_name(id_proof_file)
            id_proof_path = f'uploads/{filename}'
            print("Saved ID proof file:", id_proof_path)  # Debug print

        # Create complaint document
        complaint_data = {
            'user_id': session['user_id'],
            'type': 'myself',
            'status': 'pending',
            'created_at': datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),
            'details': {
                'personal_info': {
                    'full_name': data.get('fullName'),
                    'email': data.get('email'),
                    'phone': data.get('phone'),
                    'address': data.get('address'),
                    'city': data.get('city'),
                    'state': data.get('state'),
                    'country': data.get('country'),
                    'pincode': data.get('pincode')
                },
                'incident': {
                    'date': data.get('incidentDate'),
                    'location': data.get('incidentLocation'),
                    'description': data.get('incidentDescription'),
                    'evidence_path': evidence_path
                },
                'id_proof_path': id_proof_path
            }
        }

        print("Complaint data to be inserted:", complaint_data)  # Debug print

        # Insert complaint into database
        result = complaint_collection.insert_one(complaint_data)
        
        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'Complaint submitted successfully',
                'complaint_id': str(result.inserted_id)
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to submit complaint'}), 500

    except Exception as e:
        print(f"Error submitting complaint: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/get_user_details')
def get_user_details():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401
        
    try:
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        return jsonify({
            'success': True,
            'name': f"{user.get('firstName', '')} {user.get('lastName', '')}",
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'address': user.get('address', '')
        })
    except Exception as e:
        print(f"Error getting user details: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/complaint/myself')
def myself_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        # Get user details from database
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return redirect(url_for('login'))
            
        # Prepare user data for the template
        user_data = {
            'name': f"{user.get('firstName', '')} {user.get('lastName', '')}",
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'address': user.get('address', '')
        }
        
        return render_template('complaint/MyselfForm.html', user_data=user_data)
    except Exception as e:
        print(f"Error in myself_form: {str(e)}")
        return redirect(url_for('home'))

@app.route('/complaint/onbehalf')
def onbehalf_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        # Get user details from database
        user = user_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return redirect(url_for('login'))
            
        # Prepare user data for the template
        user_data = {
            'name': f"{user.get('firstName', '')} {user.get('lastName', '')}",
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'address': user.get('address', '')
        }
        
        return render_template('complaint/onbehalfForm.html', user_data=user_data)
    except Exception as e:
        print(f"Error in onbehalf_form: {str(e)}")
        return redirect(url_for('home'))

@app.route('/view_document/<filename>')
def view_document(filename):
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
        
    try:
        # Get the full path to the document
        document_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Check if file exists
        if not os.path.exists(document_path):
            flash('Document not found', 'error')
            return redirect(url_for('profile'))
            
        # Send the file
        return send_file(document_path)
        
    except Exception as e:
        print(f"DEBUG: Error viewing document: {str(e)}")
        flash('Error viewing document', 'error')
        return redirect(url_for('profile'))

@app.route('/chairperson_dashboard')
def chairperson_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        # Get all complaints from the database
        complaints = list(complaint_collection.find().sort('created_at', -1))
        
        # Format complaints for display
        formatted_complaints = []
        for complaint in complaints:
            formatted_complaint = {
                '_id': str(complaint['_id']),
                'created_at': complaint.get('created_at', ''),
                'status': complaint.get('status', 'pending'),
                'details': complaint.get('details', {})
            }
            formatted_complaints.append(formatted_complaint)
            
        return render_template('commitee/chairpersonDashboard.html', 
                            complaints=formatted_complaints)
                            
    except Exception as e:
        print(f"Error in chairperson_dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard')
        return render_template('commitee/chairpersonDashboard.html', complaints=[])

@app.route('/chairperson/view_complaint/<complaint_id>')
def chairperson_view_complaint(complaint_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        complaint = complaint_collection.find_one({'_id': ObjectId(complaint_id)})
        if not complaint:
            flash('Complaint not found')
            return redirect(url_for('chairperson_dashboard'))
            
        return render_template('commitee/view_complaint.html', complaint=complaint)
        
    except Exception as e:
        print(f"Error viewing complaint: {str(e)}")
        flash('An error occurred while viewing the complaint')
        return redirect(url_for('chairperson_dashboard'))

@app.route('/download_file/<path:filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    try:
        safe_path = safe_join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(safe_path):
            flash('File not found')
            return redirect(url_for('chairperson_dashboard'))
            
        return send_file(safe_path, as_attachment=True)
        
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        flash('An error occurred while downloading the file')
        return redirect(url_for('chairperson_dashboard'))

@app.route('/update_complaint_status/<complaint_id>', methods=['POST'])
def update_complaint_status(complaint_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
        
    try:
        data = request.get_json()
        new_status = data.get('status')
        remarks = data.get('remarks')
        
        if not new_status:
            return jsonify({'success': False, 'message': 'Status is required'}), 400
            
        result = complaint_collection.update_one(
            {'_id': ObjectId(complaint_id)},
            {
                '$set': {
                    'status': new_status,
                    'updated_at': datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),
                    'remarks': remarks
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True, 'message': 'Status updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Complaint not found'}), 404
            
    except Exception as e:
        print(f"Error updating complaint status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
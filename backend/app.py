import os
from flask import Flask, render_template, request, jsonify,send_from_directory,abort,redirect,flash,url_for,session
from werkzeug.utils import secure_filename, safe_join
from pymongo import MongoClient
from flask_cors import CORS
import random
import re
import smtplib
from flask_pymongo import PyMongo
from flask_session import Session
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import pytz
import time
from pymongo import WriteConcern
from bson.objectid import ObjectId
from flask_login import LoginManager, login_user, login_required, logout_user, current_user,UserMixin
from flask_sqlalchemy import SQLAlchemy
import random
from flask_mail import Mail, Message
from pymongo import MongoClient
from flask_wtf.csrf import CSRFProtect, CSRFError
from datetime import timedelta
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests
import json
import calendar


app = Flask(__name__, 
            template_folder=os.path.join(os.getcwd(), 'templates'),  # Path to templates folder
            static_folder=os.path.join(os.getcwd(), 'static'))  # Path to static folder

# Set configurations before initializing extensions
app.config.update(
    SECRET_KEY='SHini260426',
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY='SHini260426',  # Can be the same as SECRET_KEY
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),  # Set session lifetime
    SESSION_TYPE='filesystem'
)

# Initialize extensions
CORS(app)
csrf = CSRFProtect(app)
Session(app)

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
            token_request,
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
                'created_at': datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
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
@app.route('/send-otp-signup', methods=['POST'])
def send_otp_signup():
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
                'email': email,
                 'otp':otp
            })
            
        except Exception as mail_error:
            print(f"Mail Error: {str(mail_error)}")
            return jsonify({'error': 'Failed to send email'}), 500
        
    except Exception as e:
        print(f"Error sending OTP: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')
        password = data.get('password')
        name = data.get('name')

        if not all([email, otp, password, name]):
            return jsonify({"error": "All fields are required!"}), 400

        # Find OTP in database
        otp_entry = otp_collection.find_one({
            'email': email,
            'otp': otp,
            'purpose': 'signup'
        })

        if not otp_entry:
            return jsonify({"error": "Invalid OTP!"}), 400

        # Check OTP expiration (5 minutes)
        otp_time = otp_entry.get('created_at')
        if (datetime.now() - otp_time).total_seconds() > 300:
            otp_collection.delete_one({'_id': otp_entry['_id']})
            return jsonify({"error": "OTP has expired!"}), 400

        # Check if user already exists
        existing_user = user_collection.find_one({'email': email})
        if existing_user:
            return jsonify({"error": "Email already registered!"}), 400

        # Create new user
        user = {
            '_id': ObjectId(),
            'email': email,
            'password': password,  # In production, hash the password
            'name': name,
            'created_at': datetime.now()
        }

        result = user_collection.insert_one(user)

        if result.inserted_id:
            # Clean up used OTP
            otp_collection.delete_one({'_id': otp_entry['_id']})           
            
            # Set session
            session['user_id'] = str(result.inserted_id)
            session['email'] = email
            session['name'] = name

            return jsonify({
                "message": "Signup successful!",
                "user_id": str(result.inserted_id)
            }), 200
        else:
            return jsonify({"error": "Failed to create user!"}), 500

    except Exception as e:
        print(f"Error in verify_otp: {str(e)}")
        return jsonify({"error": str(e)}), 500

########################### Login functionalities ############################################################
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
                    'purpose': 'login'
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
# Update your login route to verify OTP
@app.route('/login', methods=['POST'])
def login_post():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        otp = data.get('otp')

        if not all([email, password, otp]):
            return jsonify({"error": "All fields are required!"}), 400

        # Verify user exists
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({"error": "User not found!"}), 404

        # Verify password
        if user['password'] != password:  # In production, use proper password hashing
            return jsonify({"error": "Invalid password!"}), 401

        # Verify OTP
        otp_entry = otp_collection.find_one({
            'email': email,
            'otp': otp,
            'purpose': 'login'
        })

        if not otp_entry:
            return jsonify({"error": "Invalid OTP!"}), 401

        # Check OTP expiration (5 minutes)
        otp_time = otp_entry.get('created_at')
        if (datetime.now() - otp_time).total_seconds() > 300:
            otp_collection.delete_one({'_id': otp_entry['_id']})
            return jsonify({"error": "OTP has expired!"}), 401

        # Set session data
        session['user_id'] = str(user['_id'])
        session['email'] = user['email']
        session['name'] = user.get('name', '')

        # Clean up used OTP
        otp_collection.delete_one({'_id': otp_entry['_id']})

        return jsonify({
            "success": True,
            "message": "Login successful!"
        })

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": str(e)}), 500



#######################################################################################
# Render index page (home page)
@app.route('/')
def index():
    return render_template('index.html')
###############################  dash board final updation ########################################################################
@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Check credentials
            if email == 'admin123@gmail.com' and password == 'admin123':
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
            'status': {'$regex': '^submitted$', '$options': 'i'}
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
                    'purpose': 'complaint'
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
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        otp = data.get('otp')
        
        if not all([name, email, otp]):
            return jsonify({"error": "All fields are required!"}), 400

        # Verify OTP
        otp_entry = otp_collection.find_one({
            'email': email,
            'otp': otp,
            'purpose': 'complaint'
        })

        if not otp_entry:
            return jsonify({"error": "Invalid OTP!"}), 400

        # Check OTP expiration (5 minutes)
        otp_time = otp_entry.get('created_at')
        if (datetime.now() - otp_time).total_seconds() > 300:
            otp_collection.delete_one({'_id': otp_entry['_id']})
            return jsonify({"error": "OTP has expired!"}), 400

        # Create a new complaint entry with only basic information
        complaint = {
            "_id": ObjectId(),
            "email": email,
            "name": name,
            "registered_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Registered"
        }

        result = complaint_collection.insert_one(complaint)
        
        if result.inserted_id:
            # Clean up used OTP
            otp_collection.delete_one({'_id': otp_entry['_id']})
            
            # Store complaint ID in session
            session['complaint_id'] = str(result.inserted_id)
            
            return jsonify({
                "message": "Complaint registered successfully!",
                "complaint_id": str(result.inserted_id)
            }), 200
        else:
            return jsonify({"error": "Failed to register complaint"}), 500

    except Exception as e:
        print(f"Error in register_complaint: {str(e)}")
        return jsonify({"error": str(e)}), 500
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
                    'full_name': f"{data['first_name']} {data['middle_name']} {data['last_name']}".strip(),
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
#####################################  home page #######################################################################
@app.route('/home')
def home():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user = user_collection.find_one({"_id": ObjectId(session['user_id'])})
    return render_template('home.html', user=user)
#####################################  logout  #######################################################################
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
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
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = user_collection.find_one({'_id': ObjectId(user_id)})
    
    # Ensure user has a profile_image field
    if user and 'profile_image' not in user:
        user['profile_image'] = 'img/default_profile.png'

    if request.method == 'POST':
        # Handle regular form submission
        if request.form:
            updates = {
                'name': request.form.get('name'),
                'phone': request.form.get('phone'),
                'gender': request.form.get('gender'),
                'dob': request.form.get('dob'),
                'address': request.form.get('address')
            }
            
            user_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': updates}
            )
            
            flash('Profile updated successfully!')
            return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/upload_profile_image', methods=['POST'])
def upload_profile_image():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    try:
        if 'profile_image' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400

        profile_image = request.files['profile_image']
        
        if profile_image.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400

        if profile_image:
            # Check if file extension is allowed
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            file_ext = os.path.splitext(profile_image.filename)[1][1:].lower()
            if file_ext not in allowed_extensions:
                return jsonify({'success': False, 'message': 'File type not allowed'}), 400

            # Create uploads directory if it doesn't exist
            upload_dir = os.path.join('static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)

            # Generate unique filename
            filename = secure_filename(f"profile_{session['user_id']}_{int(time.time())}.{file_ext}")
            
            # Save the file
            profile_image.save(os.path.join(upload_dir, filename))

            # Update user's profile image in database with the correct path
            image_path = f'uploads/{filename}'  # Relative path from static directory
            user_collection.update_one(
                {'_id': ObjectId(session['user_id'])},
                {'$set': {'profile_image': image_path}}
            )

            return jsonify({'success': True, 'message': 'Profile image updated successfully'})

    except Exception as e:
        print(f"Error uploading profile image: {str(e)}")  # Add logging
        return jsonify({'success': False, 'message': str(e)}), 500

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
                'password': request.form.get('password'),  # In production, hash this password
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
        return redirect(url_for('nodal_login'))

    try:
        # Get nodal officer details
        nodal_officer = nodal_collection.find_one({'email': session['nodal_email']})
        if not nodal_officer:
            return redirect(url_for('nodal_login'))

        # Get complaints matching the nodal officer's organization
        complaints = list(complaint_collection.find({
            'details.organization': {'$regex': f'^{nodal_officer["organization"]}'}
        }).sort('registered_at', -1))  # Sort by registration date, newest first

        # Calculate analytics
        total_cases = len(complaints)
        total_resolved = sum(1 for c in complaints if c.get('status', '').lower() == 'resolved')
        total_pending = total_cases - total_resolved

        # Format complaints for display
        formatted_complaints = []
        for complaint in complaints:
            try:
                formatted_complaint = {
                    'id': str(complaint.get('_id')),
                    'name': complaint.get('name', 'N/A'),
                    'email': complaint.get('email', 'N/A'),
                    'details': complaint.get('details', {}),
                    'submission': complaint.get('submission', {}),
                    'status': complaint.get('status', 'Registered'),
                    'registered_at': complaint.get('registered_at', 'N/A'),
                    'complaint_text': complaint.get('submission', {}).get('complaint_text', '')
                }
                formatted_complaints.append(formatted_complaint)
            except Exception as e:
                print(f"Error formatting complaint: {str(e)}")
                continue

        # Prepare analytics data
        analytics = {
            'total_cases': total_cases,
            'total_resolved': total_resolved,
            'total_pending': total_pending,
            'resolution_rate': (total_resolved / total_cases * 100) if total_cases > 0 else 0
        }

        # Get monthly trends
        monthly_trends = {}
        for complaint in complaints:
            try:
                date = datetime.strptime(complaint.get('registered_at', ''), "%Y-%m-%d %H:%M:%S")
                month_key = date.strftime("%B %Y")
                if month_key not in monthly_trends:
                    monthly_trends[month_key] = {'total': 0, 'resolved': 0}
                monthly_trends[month_key]['total'] += 1
                if complaint.get('status', '').lower() == 'resolved':
                    monthly_trends[month_key]['resolved'] += 1
            except Exception as e:
                print(f"Error processing date: {e}")

        analytics['monthly_trends'] = monthly_trends

        return render_template('nodal_dashboard.html',
                             nodal_officer=nodal_officer,
                             complaints=formatted_complaints,
                             analytics=analytics)

    except Exception as e:
        print(f"Error in nodal_dashboard: {e}")
        flash('An error occurred while loading the dashboard', 'error')
        return redirect(url_for('nodal_login'))

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
            if status.lower() == 'resolved':
                update_data['$set']['resolved_at'] = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
                update_data['$set']['resolved_by'] = session.get('nodal_email')
        
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

##################################################################################################################
if __name__ == '__main__':
    app.run(debug=True)
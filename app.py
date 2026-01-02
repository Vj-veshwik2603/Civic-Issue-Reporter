from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models.models import db, User, Issue
import os
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'civic-issue-reporter-secret-key-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///civic_issues.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Mock AI Service
def analyze_image(image_path):
    """
    Mock AI analysis. In production, this would call a Vision API.
    """
    issues = [
        {'type': 'Pothole', 'severity': 'High', 'risk': 'Traffic', 'dept': 'Roads'},
        {'type': 'Garbage', 'severity': 'Medium', 'risk': 'Hygiene', 'dept': 'Sanitation'},
        {'type': 'Streetlight', 'severity': 'Low', 'risk': 'Safety', 'dept': 'Electricity'},
        {'type': 'Water Leak', 'severity': 'High', 'risk': 'Water Supply', 'dept': 'Water Dept'}
    ]
    # Deterministic mock based on filename length or random
    return random.choice(issues)

# Routes - Auth
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'officer':
                return redirect(url_for('officer_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'citizen') # Default to citizen
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('home'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Routes - Views
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/officer')
@login_required
def officer_dashboard():
    if current_user.role != 'officer':
        return redirect(url_for('home'))
    issues = Issue.query.order_by(Issue.created_at.desc()).all() # In real app, filter by dept
    return render_template('officer.html', issues=issues)

@app.route('/api/report', methods=['POST'])
@login_required
def report_issue():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
        
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    # Save image (mock path for now)
    filename = 'mock_upload.jpg'
    file_path = os.path.join('static', filename)
    file.save(file_path)
    
    # AI Analysis
    ai_result = analyze_image(file_path)
    
    # Calculate priority (Mock logic)
    priority = 0
    if ai_result['severity'] == 'High': priority += 50
    if ai_result['risk'] == 'Safety': priority += 30
    
    # Create Issue
    user_desc = request.form.get('description')
    default_desc = f"Detected {ai_result['type']} with {ai_result['severity']} severity."
    
    new_issue = Issue(
        title=f"Reported {ai_result['type']}",
        description=user_desc if user_desc else default_desc,
        image_path=filename,
        latitude=float(request.form.get('lat', 0)),
        longitude=float(request.form.get('lng', 0)),
        issue_type=ai_result['type'],
        severity=ai_result['severity'],
        risk_level=ai_result['risk'],
        assigned_department=ai_result['dept'],
        priority_score=priority,
        reporter_id=current_user.id
    )
    
    db.session.add(new_issue)
    db.session.commit()
    
    return jsonify({'message': 'Issue reported successfully', 'issue_id': new_issue.id})

@app.route('/api/issue/<int:issue_id>/update', methods=['POST'])
@login_required
def update_issue(issue_id):
    if current_user.role != 'officer':
        return jsonify({'error': 'Unauthorized'}), 403
        
    issue = Issue.query.get_or_404(issue_id)
    data = request.json
    
    if 'status' in data:
        issue.status = data['status']
    if 'severity' in data:
        issue.severity = data['severity']
        
    db.session.commit()
    return jsonify({'message': 'Issue updated successfully'})

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
        
    # Fetch real stats
    total_issues = Issue.query.count()
    resolved_count = Issue.query.filter_by(status='Resolved').count()
    critical_count = Issue.query.filter_by(severity='High').count()
    
    # Get all high priority issues
    high_priority_issues = Issue.query.filter_by(severity='High').order_by(Issue.created_at.desc()).all()
    
    # Calculate top department (simple version)
    from sqlalchemy import func
    top_dept_query = db.session.query(Issue.assigned_department, func.count(Issue.id)).group_by(Issue.assigned_department).order_by(func.count(Issue.id).desc()).first()
    top_dept = top_dept_query[0] if top_dept_query else "N/A"
    
    return render_template('admin.html', 
                         total_issues=total_issues,
                         resolved_count=resolved_count,
                         critical_count=critical_count,
                         high_priority_issues=high_priority_issues,
                         top_dept=top_dept)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False) # citizen, officer, admin

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True) # AI summary
    image_path = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    
    # AI Classification
    issue_type = db.Column(db.String(50), nullable=False) # Pothole, Garbage, etc.
    severity = db.Column(db.String(20), nullable=False) # Low, Medium, High
    risk_level = db.Column(db.String(20), nullable=False) # Safety, Hygiene, Traffic
    priority_score = db.Column(db.Integer, default=0)
    
    # Status
    status = db.Column(db.String(20), default='Reported') # Reported, In Progress, Resolved
    assigned_department = db.Column(db.String(50), nullable=True)
    
    # Meta
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_count = db.Column(db.Integer, default=1) # For merging duplicates

    reporter = db.relationship('User', backref=db.backref('issues', lazy=True))

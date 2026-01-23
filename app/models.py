from app import db
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False)

    # Tenant Isolation (Organization)
    organization_id = db.Column(db.String(50), default="DEFAULT_ORG")

    # Student Fields
    roll_no = db.Column(db.String(20))
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))

    # Teacher Fields
    assigned_classes = db.Column(db.JSON, nullable=True, default=list)
    email = db.Column(db.String(120))
    subject = db.Column(db.String(100))
    bio = db.Column(db.Text)

    # Security Fields
    mfa_secret = db.Column(db.String(32), nullable=True)  # For Google Authenticator
    mfa_enabled = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(100), nullable=False)  # e.g., "LOGIN", "DELETE_USER"
    ip_address = db.Column(db.String(50))
    details = db.Column(db.Text)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    division = db.Column(db.String(10), nullable=False)
    subject_name = db.Column(db.String(100), nullable=False)
    teacher_name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Encryption at Rest: This field will now store ENCRYPTED strings
    answer_key_content = db.Column(db.Text, nullable=True)

    questionnaire_file = db.Column(db.LargeBinary, nullable=True)
    questionnaire_filename = db.Column(db.String(100))

    # Randomization Config
    randomize_questions = db.Column(db.Boolean, default=False)

    submissions = db.relationship('Submission', backref='assignment', lazy=True, cascade="all, delete-orphan")


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_file = db.Column(db.LargeBinary, nullable=True)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Float, default=0.0)
    detailed_feedback = db.Column(db.JSON, nullable=True)

    # Browser Lockdown Forensics
    tab_switches = db.Column(db.Integer, default=0)
    suspicious_activity = db.Column(db.Boolean, default=False)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    lecture_subject = db.Column(db.String(100), nullable=False, default="General")
    status = db.Column(db.String(10), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))
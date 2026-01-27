from app import db
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    organization_id = db.Column(db.String(50), default="DEFAULT_ORG")

    # Contact & Verification
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)

    # Student Fields
    roll_no = db.Column(db.String(20))
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))

    # Teacher Fields
    assigned_classes = db.Column(db.JSON, nullable=True, default=list)
    subject = db.Column(db.String(100))
    bio = db.Column(db.Text)

    # Security Fields
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)


class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    division = db.Column(db.String(10), nullable=False)
    subjects = db.relationship('Subject', backref='classroom', lazy=True, cascade="all, delete-orphan")


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(100), nullable=False)
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

    answer_key_content = db.Column(db.Text, nullable=True)
    questionnaire_file = db.Column(db.LargeBinary, nullable=True)
    questionnaire_filename = db.Column(db.String(100))

    # Test Module
    atype = db.Column(db.String(20), default="assignment")
    duration_minutes = db.Column(db.Integer, default=0)

    submissions = db.relationship('Submission', backref='assignment', lazy=True, cascade="all, delete-orphan")


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_file = db.Column(db.LargeBinary, nullable=True)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Float, default=0.0)
    detailed_feedback = db.Column(db.JSON, nullable=True)

    # Forensics
    tab_switches = db.Column(db.Integer, default=0)
    suspicious_activity = db.Column(db.Boolean, default=False)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    lecture_subject = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))
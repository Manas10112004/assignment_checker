from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' or 'teacher'

    # Profile info
    email = db.Column(db.String(120))
    subject = db.Column(db.String(100))
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))
    roll_no = db.Column(db.String(20))
    bio = db.Column(db.Text)
    image_url = db.Column(db.String(200))

    assignments = db.relationship('Assignment', backref='teacher', lazy=True)
    submissions = db.relationship('Submission', backref='student', lazy=True)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    division = db.Column(db.String(10), nullable=False)
    subject_name = db.Column(db.String(100), nullable=False)
    teacher_name = db.Column(db.String(100), nullable=False)

    answer_key = db.Column(db.String(200))  # storing filename
    questionnaire_file = db.Column(db.String(200))  # storing filename

    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submissions = db.relationship('Submission', backref='assignment', lazy=True, cascade="all, delete-orphan")


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    submitted_file = db.Column(db.LargeBinary, nullable=False)
    score = db.Column(db.Float)

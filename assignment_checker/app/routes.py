from flask import Blueprint, render_template, request, redirect, session, flash, url_for, send_file, current_app
from werkzeug.utils import secure_filename
from io import BytesIO
from PIL import Image
import base64
import os
from datetime import datetime

from app.models import db, User, Assignment, Submission
from app.ai_evaluator import compute_score

routes = Blueprint('routes', __name__)
UPLOAD_DIR = os.path.join('app', 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------- AUTH --------------------

@routes.route('/')
def home():
    return redirect(url_for('routes.login'))

@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect('/register')

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful.', 'success')
        return redirect('/login')

    return render_template('register.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            flash('Login successful.', 'success')
            return redirect('/teacher/dashboard' if user.role == 'teacher' else '/student/dashboard')
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@routes.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect('/login')

# -------------------- TEACHER DASHBOARD --------------------

@routes.route('/teacher/dashboard')
def teacher_dashboard():
    if session.get('role') != 'teacher':
        return redirect('/login')
    teacher = User.query.get(session['user_id'])
    return render_template('teacher_dashboard.html', teacher=teacher, page='profile', now=datetime.now())

# -------------------- ASSIGNMENT CREATE --------------------

@routes.route('/teacher/create-assignment', methods=['GET', 'POST'])
def create_assignment():
    if session.get('role') != 'teacher':
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title']
        class_name = request.form['class_name']
        division = request.form['division']
        teacher_name = request.form['teacher_name']
        subject_name = request.form['subject_name']

        answer_key_file = request.files.get('answer_key')
        questionnaire_file = request.files.get('questionnaire_file')

        if not questionnaire_file or questionnaire_file.filename == '':
            flash("Questionnaire file is required.",'danger')
            return redirect('/teacher/create-assignment')

        answer_key_filename = None
        questionnaire_filename = None

        if answer_key_file and answer_key_file.filename != '':
            answer_key_filename = secure_filename(answer_key_file.filename)
            answer_key_file.save(os.path.join(UPLOAD_DIR, answer_key_filename))

        if questionnaire_file and questionnaire_file.filename != '':
            questionnaire_filename = secure_filename(questionnaire_file.filename)
            questionnaire_file.save(os.path.join(UPLOAD_DIR, questionnaire_filename))

        assignment = Assignment(
            title=title,
            class_name=class_name,
            division=division,
            teacher_name=teacher_name,
            subject_name=subject_name,
            teacher_id=session['user_id'],
            answer_key=answer_key_filename,
            questionnaire_file=questionnaire_filename
        )
        db.session.add(assignment)
        db.session.commit()

        flash('Assignment created successfully','success')
        return redirect('/teacher/create-assignment')

    assignments = Assignment.query.filter_by(teacher_id=session['user_id']).all()
    return render_template('create_assignment.html', assignments=assignments)

# -------------------- ASSIGNMENT EDIT --------------------

@routes.route('/teacher/assignments/<int:assignment_id>/edit', methods=['GET', 'POST'])
def edit_assignment(assignment_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect(url_for('routes.login'))

    assignment = Assignment.query.get_or_404(assignment_id)

    if request.method == 'POST':
        assignment.title = request.form['title']
        assignment.class_name = request.form['class_name']
        assignment.division = request.form['division']
        assignment.subject_name = request.form['subject_name']
        assignment.teacher_name = request.form['teacher_name']

        answer_file = request.files.get('answer_key')
        if answer_file and answer_file.filename != '':
            filename = secure_filename(answer_file.filename)
            answer_file.save(os.path.join(UPLOAD_DIR, filename))
            assignment.answer_key = filename

        question_file = request.files.get('questionnaire_file')
        if question_file and question_file.filename != '':
            filename = secure_filename(question_file.filename)
            question_file.save(os.path.join(UPLOAD_DIR, filename))
            assignment.questionnaire_file = filename

        db.session.commit()
        flash('Assignment updated successfully.')
        return redirect(url_for('routes.view_assignments'))

    return render_template('edit_assignment.html', assignment=assignment)

# -------------------- VIEW & DELETE --------------------

@routes.route('/teacher/assignments')
def view_assignments():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect(url_for('routes.login'))

    teacher_id = session['user_id']
    assignments = Assignment.query.filter_by(teacher_id=teacher_id).all()
    return render_template('view_assignments.html', assignments=assignments)

@routes.route('/teacher/delete-assignment/<int:assignment_id>', methods=['POST'])
def delete_assignment(assignment_id):
    if session.get('role') != 'teacher':
        return redirect('/login')

    assignment = Assignment.query.get(assignment_id)
    if assignment and assignment.teacher_id == session['user_id']:
        db.session.delete(assignment)
        db.session.commit()
        flash('Assignment deleted successfully.','success')

    return redirect('/teacher/create-assignment')

@routes.route('/teacher/view-submissions/<int:assignment_id>')
def view_submissions(assignment_id):
    if session.get('role') != 'teacher':
        return redirect('/login')

    assignment = Assignment.query.get_or_404(assignment_id)
    if assignment.teacher_id != session['user_id']:
        flash("You are not authorized to view this assignment.")
        return redirect('/teacher/dashboard')

    submissions = assignment.submissions
    return render_template('view_submissions.html', assignment=assignment, submissions=submissions)

# -------------------- PROFILE --------------------

@routes.route('/teacher/upload-photo', methods=['POST'])
def upload_teacher_photo():
    if session.get('role') != 'teacher':
        return redirect('/login')

    data_url = request.form.get('cropped_image')
    if data_url:
        header, encoded = data_url.split(",", 1)
        binary_data = base64.b64decode(encoded)
        img = Image.open(BytesIO(binary_data))

        filename = f"profile_{session['user_id']}.png"
        filepath = os.path.join(UPLOAD_DIR, filename)
        img.save(filepath, format="PNG")

        user = User.query.get(session['user_id'])
        user.image_url = f'/static/uploads/{filename}'
        db.session.commit()
        flash("Profile photo updated successfully.")
    return redirect('/teacher/dashboard')

@routes.route('/teacher/update-profile', methods=['POST'])
def update_teacher_profile():
    if session.get('role') != 'teacher':
        return redirect('/login')

    teacher = User.query.get(session['user_id'])
    if teacher:
        teacher.email = request.form.get('email')
        teacher.subject = request.form.get('subject')
        teacher.class_name = request.form.get('class_name')
        teacher.division = request.form.get('division')
        teacher.bio = request.form.get('bio')
        db.session.commit()
        flash('Profile updated successfully.')

    return redirect('/teacher/dashboard')

# -------------------- STUDENT DASHBOARD --------------------

@routes.route('/student/dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if session.get('role') != 'student':
        return redirect('/login')

    student = User.query.get(session['user_id'])

    if request.method == 'POST':
        assignment_id = int(request.form['assignment_id'])

        existing_submission = Submission.query.filter_by(
            assignment_id=assignment_id,
            student_id=session['user_id']
        ).first()

        if existing_submission:
            flash("You have already submitted this assignment.")
            return redirect('/student/dashboard')

        uploaded_file = request.files['student_answer']
        if uploaded_file:
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(UPLOAD_DIR, filename)
            uploaded_file.save(filepath)

            try:
                with open(filepath, 'rb') as f:
                    raw_bytes = f.read()

                try:
                    student_answer_text = raw_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    student_answer_text = raw_bytes.decode('latin1')

                assignment = Assignment.query.get(assignment_id)

                if assignment and assignment.answer_key:
                    key_path = os.path.join(UPLOAD_DIR, assignment.answer_key)
                    try:
                        with open(key_path, 'r', encoding='utf-8') as f:
                            answer_key_text = f.read()
                    except UnicodeDecodeError:
                        with open(key_path, 'r', encoding='latin1') as f:
                            answer_key_text = f.read()

                    score = compute_score(student_answer_text, answer_key_text)
                else:
                    score = 0.0

                new_submission = Submission(
                    assignment_id=assignment_id,
                    student_id=session['user_id'],
                    submitted_file=raw_bytes,
                    score=score
                )
                db.session.add(new_submission)
                db.session.commit()

                flash(f"Assignment submitted successfully. Your score: {score}%")
            except Exception as e:
                flash(f"Error during evaluation: {str(e)}")

        return redirect('/student/dashboard')

    assignments = Assignment.query.all()
    submissions = Submission.query.filter_by(student_id=session['user_id']).all()
    submitted_ids = {s.assignment_id for s in submissions}
    score_map = {s.assignment_id: s.score for s in submissions}

    return render_template(
        'student_dashboard.html',
        assignments=assignments,
        student=student,
        submitted_ids=submitted_ids,
        score_map=score_map
    )

@routes.route('/student/upload-photo', methods=['POST'])
def upload_student_photo():
    if session.get('role') != 'student':
        return redirect('/login')

    data_url = request.form.get('cropped_image')
    if data_url:
        header, encoded = data_url.split(",", 1)
        binary_data = base64.b64decode(encoded)
        img = Image.open(BytesIO(binary_data))

        filename = f"student_{session['user_id']}.png"
        filepath = os.path.join(UPLOAD_DIR, filename)
        img.save(filepath, format="PNG")

        user = User.query.get(session['user_id'])
        user.image_url = f'/static/uploads/{filename}'
        db.session.commit()
        flash("Profile photo updated successfully.")
    return redirect('/student/dashboard')

@routes.route('/student/update-profile', methods=['POST'])
def update_student_profile():
    if session.get('role') != 'student':
        return redirect('/login')

    student = User.query.get(session['user_id'])
    if student:
        student.class_name = request.form.get('class_name')
        student.division = request.form.get('division')
        student.roll_no = request.form.get('roll_no')
        student.bio = request.form.get('bio')
        db.session.commit()
        flash('Profile updated successfully.')

    return redirect('/student/dashboard')

@routes.route('/student/download/<int:assignment_id>')
def download_assignment(assignment_id):
    assignment = Assignment.query.get(assignment_id)
    if assignment and assignment.questionnaire_file:
        filepath = os.path.join(UPLOAD_DIR, assignment.questionnaire_file)
        return send_file(filepath, as_attachment=True)
    else:
        flash("Assignment not found or no file available.")
        return redirect('/student/dashboard')

@routes.route('/student/assignments')
def student_assignments():
    if session.get('role') != 'student':
        return redirect('/login')

    student_id = session['user_id']
    student = User.query.get(student_id)

    assignments = Assignment.query.all()
    submissions = Submission.query.filter_by(student_id=student_id).all()
    submitted_ids = {s.assignment_id for s in submissions}
    score_map = {s.assignment_id: s.score for s in submissions}

    return render_template(
        'student_assignments.html',
        assignments=assignments,
        student=student,
        submitted_ids=submitted_ids,
        score_map=score_map
    )

@routes.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('routes.forgot_password'))

        user = User.query.filter_by(username=username).first()
        if user:
            user.password = new_password  # hash in real apps
            db.session.commit()
            flash('Password reset successful.', 'success')
            return redirect(url_for('routes.login'))
        else:
            flash('Username not found.', 'danger')

    return render_template('forgot_password.html')
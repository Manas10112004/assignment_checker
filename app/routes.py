from flask import Blueprint, render_template, request, redirect, session, flash, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO
import json
import os
import pypdf
import pytesseract
from pdf2image import convert_from_bytes
from PIL import Image
from datetime import datetime

# Import models & AI
from app.models import db, User, Assignment, Submission, Attendance
from app.ai_evaluator import compute_score, generate_answer_key

routes = Blueprint('routes', __name__)


# --- HELPER: OCR & Text Extraction ---
def extract_text_from_file(file_storage):
    """
    Extracts text from PDF (Standard + OCR) or TXT files.
    """
    filename = file_storage.filename.lower()
    file_bytes = file_storage.read()
    file_storage.seek(0)  # Reset cursor for saving later

    text = ""

    # 1. Handle PDF
    if filename.endswith('.pdf'):
        try:
            # A. Try Standard Text Extraction
            pdf_reader = pypdf.PdfReader(BytesIO(file_bytes))
            for page in pdf_reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + "\n"

            # B. If empty, use OCR (Scanned PDF)
            if len(text.strip()) < 20:
                print("Text empty. Running OCR...")
                try:
                    images = convert_from_bytes(file_bytes)
                    for img in images:
                        text += pytesseract.image_to_string(img) + "\n"
                except Exception as e:
                    print(f"OCR Error: {e}")

            return text
        except Exception as e:
            print(f"PDF Read Error: {e}")
            return ""

    # 2. Handle Images (Direct Uploads)
    elif filename.endswith(('.png', '.jpg', '.jpeg')):
        try:
            image = Image.open(BytesIO(file_bytes))
            return pytesseract.image_to_string(image)
        except:
            return ""

    # 3. Handle Text Files
    else:
        try:
            return file_bytes.decode('utf-8', errors='ignore')
        except:
            return ""


# -------------------- AUTH & DASHBOARDS --------------------

@routes.route('/')
def home():
    return redirect(url_for('routes.login'))


@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            return redirect('/teacher/dashboard' if user.role == 'teacher' else '/student/dashboard')
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')


@routes.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Simple Logic for Class/Div/Roll
        class_name = request.form.get('class_name', '').upper()
        division = request.form.get('division', '').upper()
        roll_no = request.form.get('roll_no')

        if User.query.filter_by(username=username).first():
            flash('Username exists.', 'danger')
            return redirect('/register')

        assigned_classes = []
        if role == 'teacher' and class_name:
            assigned_classes.append({"class_name": class_name, "division": division})

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            class_name=class_name,
            division=division,
            roll_no=roll_no,
            assigned_classes=assigned_classes
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registered! Please login.', 'success')
        return redirect('/login')
    return render_template('register.html')


# -------------------- TEACHER ROUTES --------------------

@routes.route('/teacher/dashboard')
def teacher_dashboard():
    if session.get('role') != 'teacher': return redirect('/login')
    teacher = User.query.get(session['user_id'])
    return render_template('teacher_dashboard.html', teacher=teacher)


@routes.route('/teacher/create-assignment', methods=['GET', 'POST'])
def create_assignment():
    if session.get('role') != 'teacher': return redirect('/login')

    if request.method == 'POST':
        # Retrieve form data
        title = request.form['title']
        cls = request.form['class_name'].strip().upper()
        div = request.form['division'].strip().upper()
        subject = request.form['subject_name']

        # File Handling
        q_file = request.files.get('questionnaire_file')
        q_blob = q_file.read() if q_file else None
        q_name = secure_filename(q_file.filename) if q_file else None
        if q_file: q_file.seek(0)  # Reset if needed

        # Answer Key
        ai_key = request.form.get('ai_generated_key')
        manual_key_file = request.files.get('answer_key')

        final_key = ""
        if ai_key and ai_key.strip():
            final_key = ai_key
        elif manual_key_file:
            final_key = extract_text_from_file(manual_key_file)

        new_assign = Assignment(
            title=title, class_name=cls, division=div, subject_name=subject,
            teacher_name=session['username'], teacher_id=session['user_id'],
            answer_key_content=final_key,
            questionnaire_file=q_blob, questionnaire_filename=q_name
        )
        db.session.add(new_assign)
        db.session.commit()
        flash('Assignment Created!', 'success')
        return redirect('/teacher/assignments')

    return render_template('create_assignment.html')


@routes.route('/teacher/generate-key', methods=['POST'])
def generate_key_api():
    # API for the AI Button in frontend
    if session.get('role') != 'teacher': return {"error": "Unauthorized"}, 401
    file = request.files['file']
    text = extract_text_from_file(file)
    if not text: return {"error": "Could not read file"}, 400
    return {"key": generate_answer_key(text)}


@routes.route('/teacher/assignments')
def view_assignments():
    if session.get('role') != 'teacher': return redirect('/login')
    assignments = Assignment.query.filter_by(teacher_id=session['user_id']).all()
    return render_template('view_assignments.html', assignments=assignments)


@routes.route('/teacher/delete-assignment/<int:id>', methods=['POST'])
def delete_assignment(id):
    if session.get('role') != 'teacher': return redirect('/login')
    assign = Assignment.query.get_or_404(id)
    if assign.teacher_id != session['user_id']: return redirect('/teacher/assignments')

    db.session.delete(assign)
    db.session.commit()
    flash('Assignment deleted.', 'success')
    return redirect('/teacher/assignments')


# -------------------- STUDENT ROUTES --------------------

@routes.route('/student/dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if session.get('role') != 'student': return redirect('/login')
    student = User.query.get(session['user_id'])

    # Handle Submission
    if request.method == 'POST':
        a_id = request.form.get('assignment_id')
        u_file = request.files.get('student_answer')

        assign = Assignment.query.get(a_id)
        student_text = extract_text_from_file(u_file)

        if not student_text.strip():
            flash("Empty or unreadable file.", "danger")
        elif not assign.answer_key_content:
            flash("Teacher hasn't provided a key yet.", "warning")
        else:
            # AI GRADING
            score, feedback = compute_score(student_text, assign.answer_key_content)

            sub = Submission(
                assignment_id=assign.id, student_id=student.id,
                submitted_file=u_file.read(),
                score=score, detailed_feedback=feedback
            )
            db.session.add(sub)
            db.session.commit()
            flash(f"Submitted! AI Score: {score}%", "success")
        return redirect('/student/dashboard')

    # Load Data
    assignments = Assignment.query.filter_by(class_name=student.class_name, division=student.division).all()
    my_subs = Submission.query.filter_by(student_id=student.id).all()
    sub_map = {s.assignment_id: s for s in my_subs}

    # Stats
    total_att = Attendance.query.filter_by(student_id=student.id).count()
    present_att = Attendance.query.filter_by(student_id=student.id, status='Present').count()
    att_pct = int((present_att / total_att) * 100) if total_att > 0 else 0

    return render_template('student_dashboard.html', student=student, assignments=assignments,
                           submitted_map=sub_map, att_pct=att_pct,
                           total_days=total_att, present_days=present_att)


@routes.route('/student/download/<int:id>')
def download_questionnaire(id):
    if session.get('role') != 'student': return redirect('/login')
    assign = Assignment.query.get_or_404(id)
    if not assign.questionnaire_file: return "No file", 404

    return send_file(
        BytesIO(assign.questionnaire_file),
        download_name=assign.questionnaire_filename,
        as_attachment=True
    )
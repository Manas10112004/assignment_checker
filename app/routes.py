from flask import Blueprint, render_template, request, redirect, session, flash, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.orm.attributes import flag_modified
from io import BytesIO
import pypdf
from pdf2image import convert_from_bytes
import uuid
from datetime import datetime

# --- IMPORTS ---
from app.models import db, User, Assignment, Submission, Attendance
from app.ai_evaluator import compute_score, generate_answer_key, extract_text_from_image

routes = Blueprint('routes', __name__)


# --- HELPER: Extract Text ---
def extract_text_from_file(file_storage):
    filename = file_storage.filename.lower()
    if filename.endswith('.pdf'):
        try:
            pdf_reader = pypdf.PdfReader(file_storage)
            text = ""
            for page in pdf_reader.pages:
                extracted = page.extract_text()
                if extracted: text += extracted + "\n"
            if len(text.strip()) < 10:
                file_storage.seek(0)
                images = convert_from_bytes(file_storage.read())
                for img in images:
                    img_byte_arr = BytesIO()
                    img.save(img_byte_arr, format='JPEG')
                    text += extract_text_from_image(img_byte_arr.getvalue()) + "\n"
            file_storage.seek(0)
            return text
        except:
            return ""
    elif filename.endswith(('.png', '.jpg', '.jpeg')):
        try:
            file_bytes = file_storage.read()
            text = extract_text_from_image(file_bytes)
            file_storage.seek(0)
            return text
        except:
            return ""
    else:
        try:
            return file_storage.read().decode('utf-8', errors='ignore')
        except:
            return ""


# --- AUTH ROUTES ---
@routes.route('/')
def home(): return redirect('/login')


@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Admin Backdoor
        if username == 'admin' and password == 'admin123':
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(username='admin', password_hash=generate_password_hash('admin123'), role='admin')
                db.session.add(admin)
                db.session.commit()
            session['user_id'] = admin.id
            session['role'] = 'admin'
            return redirect('/admin/dashboard')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username

            if user.role == 'admin': return redirect('/admin/dashboard')
            if user.role == 'teacher': return redirect('/teacher/dashboard')
            return redirect('/student/dashboard')

        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@routes.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form.get('username')).first():
            flash('Username taken', 'danger')
            return redirect('/register')

        role = request.form.get('role')
        assigned_classes = []
        if role == 'teacher' and request.form.get('class_name'):
            assigned_classes.append({
                "class_name": request.form.get('class_name').strip().upper(),
                "division": request.form.get('division').strip().upper()
            })

        user = User(
            username=request.form.get('username'),
            password_hash=generate_password_hash(request.form.get('password')),
            role=role,
            class_name=request.form.get('class_name'),
            division=request.form.get('division'),
            roll_no=request.form.get('roll_no'),
            assigned_classes=assigned_classes
        )
        db.session.add(user)
        db.session.commit()
        flash('Registered!', 'success')
        return redirect('/login')
    return render_template('register.html')


@routes.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            token = str(uuid.uuid4())
            user.reset_token = token
            db.session.commit()
            reset_link = url_for('routes.reset_password', token=token, _external=True)
            flash(f"DEMO MODE: Password Reset Link: {reset_link}", "info")
        else:
            flash("User not found.", "danger")
    return render_template('forgot_password.html')


@routes.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Invalid token.", "danger")
        return redirect('/login')
    if request.method == 'POST':
        new_pass = request.form.get('password')
        user.password_hash = generate_password_hash(new_pass)
        user.reset_token = None
        db.session.commit()
        flash("Password reset successful!", "success")
        return redirect('/login')
    return render_template('reset_password.html')


# --- TEACHER ROUTES ---
@routes.route('/teacher/dashboard')
def teacher_dashboard():
    if session.get('role') != 'teacher': return redirect('/login')
    teacher = User.query.get(session['user_id'])
    return render_template('teacher_dashboard.html', teacher=teacher)


@routes.route('/teacher/update-profile', methods=['POST'])
def update_teacher_profile():
    if session.get('role') != 'teacher': return redirect('/login')
    teacher = User.query.get(session['user_id'])

    teacher.email = request.form.get('email')
    teacher.subject = request.form.get('subject')
    teacher.bio = request.form.get('bio')

    new_class = request.form.get('new_class_name')
    new_div = request.form.get('new_division')

    if new_class and new_div:
        cls_obj = {"class_name": new_class.strip().upper(), "division": new_div.strip().upper()}
        if teacher.assigned_classes is None: teacher.assigned_classes = []
        current_list = list(teacher.assigned_classes)
        current_list.append(cls_obj)
        teacher.assigned_classes = current_list
        flag_modified(teacher, "assigned_classes")

    db.session.commit()
    return redirect('/teacher/dashboard')


@routes.route('/teacher/create-assignment', methods=['GET', 'POST'])
def create_assignment():
    if session.get('role') != 'teacher': return redirect('/login')
    teacher = User.query.get(session['user_id'])

    if request.method == 'POST':
        try:
            file = request.files.get('questionnaire_file')
            key_text = request.form.get('ai_generated_key')

            new_assign = Assignment(
                title=request.form.get('title'),
                class_name=request.form.get('class_name').strip().upper(),
                division=request.form.get('division').strip().upper(),
                subject_name=request.form.get('subject_name'),
                teacher_name=teacher.username,
                teacher_id=teacher.id,
                answer_key_content=key_text,
                questionnaire_file=file.read() if file else None,
                questionnaire_filename=secure_filename(file.filename) if file else "unknown.txt"
            )
            db.session.add(new_assign)
            db.session.commit()
            flash("Assignment Created!", "success")
            return redirect('/teacher/assignments')
        except Exception as e:
            flash(f"Error: {e}", "danger")
    return render_template('create_assignment.html')


@routes.route('/teacher/generate-key', methods=['POST'])
def generate_key_api():
    if session.get('role') != 'teacher': return {"error": "Unauthorized"}, 401
    file = request.files.get('file')
    if not file: return {"error": "No file"}, 400
    text = extract_text_from_file(file)
    return {"key": generate_answer_key(text)}


@routes.route('/teacher/assignments')
def view_assignments():
    if session.get('role') != 'teacher': return redirect('/login')
    assignments = Assignment.query.filter_by(teacher_id=session['user_id']).all()
    return render_template('view_assignments.html', assignments=assignments)


@routes.route('/teacher/assignments/<int:id>/edit', methods=['GET', 'POST'])
def edit_assignment(id):
    if session.get('role') != 'teacher': return redirect('/login')
    assignment = Assignment.query.get_or_404(id)
    if request.method == 'POST':
        assignment.title = request.form.get('title')
        assignment.class_name = request.form.get('class_name')
        assignment.division = request.form.get('division')
        assignment.subject_name = request.form.get('subject_name')
        db.session.commit()
        flash("Updated!", "success")
        return redirect('/teacher/assignments')
    return render_template('edit_assignment.html', assignment=assignment)


@routes.route('/teacher/assignments/<int:id>/submissions')
def view_submissions(id):
    if session.get('role') != 'teacher': return redirect('/login')
    assignment = Assignment.query.get_or_404(id)
    submissions = Submission.query.filter_by(assignment_id=id).all()
    return render_template('view_submissions.html', assignment=assignment, submissions=submissions)


@routes.route('/teacher/delete-assignment/<int:id>', methods=['POST'])
def delete_assignment(id):
    if session.get('role') != 'teacher': return redirect('/login')
    assign = Assignment.query.get_or_404(id)
    if assign.teacher_id == session['user_id']:
        db.session.delete(assign)
        db.session.commit()
    return redirect('/teacher/assignments')


# --- ATTENDANCE FIX (Crash Proof) ---
@routes.route('/teacher/attendance', methods=['GET', 'POST'])
def teacher_attendance():
    if session.get('role') != 'teacher': return redirect('/login')
    teacher = User.query.get(session['user_id'])

    cls = request.args.get('class_name')
    div = request.args.get('div')
    students = []

    if cls and div:
        students = User.query.filter_by(role='student', class_name=cls, division=div).all()

    if request.method == 'POST':
        # Safely get data
        date_str = request.form.get('date')
        subject_name = request.form.get('subject')  # This was the cause of the 400 error

        # Check if fields are missing
        if not date_str or not subject_name:
            flash("Error: You must provide both a Date and a Subject/Lecture name.", "danger")
            return redirect(f"/teacher/attendance?class_name={cls}&div={div}")

        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        for student in students:
            status = request.form.get(f"status_{student.id}")
            if status:
                rec = Attendance(
                    date=date,
                    lecture_subject=subject_name,
                    status=status,
                    student_id=student.id,
                    teacher_id=teacher.id,
                    class_name=cls,
                    division=div
                )
                db.session.add(rec)
        db.session.commit()
        flash(f"Attendance for {subject_name} Saved!", "success")
        return redirect(f"/teacher/attendance?class_name={cls}&div={div}")

    return render_template('teacher_attendance.html', teacher=teacher, students=students,
                           selected_class=cls, selected_div=div, now=datetime.now())


# --- STUDENT ROUTES ---
@routes.route('/student/dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if session.get('role') != 'student': return redirect('/login')
    student = User.query.get(session['user_id'])

    if request.method == 'POST':
        aid = request.form.get('assignment_id')
        file = request.files.get('student_answer')
        assign = Assignment.query.get(aid)

        student_text = extract_text_from_file(file)
        score, feedback = compute_score(student_text, assign.answer_key_content)

        sub = Submission(assignment_id=aid, student_id=student.id,
                         submitted_file=file.read(), score=score, detailed_feedback=feedback)
        db.session.add(sub)
        db.session.commit()
        flash(f"Graded: {score}%", "success")
        return redirect('/student/dashboard')

    assigns = Assignment.query.filter_by(class_name=student.class_name, division=student.division).all()
    my_subs = {s.assignment_id: s for s in Submission.query.filter_by(student_id=student.id).all()}

    total = Attendance.query.filter_by(student_id=student.id).count()
    present = Attendance.query.filter_by(student_id=student.id, status='Present').count()
    pct = int((present / total) * 100) if total > 0 else 0
    return render_template('student_dashboard.html', student=student, assignments=assigns, submitted_map=my_subs,
                           att_pct=pct, present_days=present, total_days=total)


@routes.route('/student/download/<int:id>')
def download_q(id):
    assign = Assignment.query.get_or_404(id)
    return send_file(BytesIO(assign.questionnaire_file), download_name=assign.questionnaire_filename,
                     as_attachment=True)


@routes.route('/api/chat', methods=['POST'])
def chat_api():
    data = request.json
    user_message = data.get('message', '')
    if not user_message: return {"response": "I didn't hear anything!"}
    from app.ai_evaluator import get_groq_client
    client = get_groq_client()
    if not client: return {"response": "Error: AI Brain is offline."}
    try:
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a helpful teaching assistant."},
                {"role": "user", "content": user_message}
            ],
            model="llama-3.3-70b-versatile",
        )
        return {"response": completion.choices[0].message.content}
    except Exception as e:
        return {"response": "Thinking error."}
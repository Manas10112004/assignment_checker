from flask import Blueprint, render_template, request, redirect, session, flash, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.orm.attributes import flag_modified
from io import BytesIO
import pypdf
from datetime import datetime

# --- IMPORTS ---
from app.models import db, User, Assignment, Submission, Attendance
# Import the updated AI functions
from app.ai_evaluator import compute_score, generate_answer_key, extract_text_from_image

routes = Blueprint('routes', __name__)


# --- HELPER: Cloud-Based Text Extractor ---
def extract_text_from_file(file_storage):
    filename = file_storage.filename.lower()

    # 1. Handle PDFs
    if filename.endswith('.pdf'):
        try:
            pdf_reader = pypdf.PdfReader(file_storage)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            file_storage.seek(0)
            return text
        except:
            return ""

    # 2. Handle Images (Send to Llama 4 Scout)
    elif filename.endswith(('.png', '.jpg', '.jpeg')):
        try:
            file_bytes = file_storage.read()
            text = extract_text_from_image(file_bytes)
            file_storage.seek(0)  # Reset cursor
            return text
        except Exception as e:
            print(f"Vision Error: {e}")
            return ""

    # 3. Handle Text Files
    else:
        try:
            content = file_storage.read().decode('utf-8', errors='ignore')
            file_storage.seek(0)
            return content
        except:
            return ""


# --- AUTH ROUTES ---
@routes.route('/')
def home(): return redirect('/login')


@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            return redirect('/teacher/dashboard' if user.role == 'teacher' else '/student/dashboard')
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@routes.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username taken', 'danger')
            return redirect('/register')

        role = request.form['role']
        assigned_classes = []
        if role == 'teacher' and request.form.get('class_name'):
            assigned_classes.append({
                "class_name": request.form.get('class_name').strip().upper(),
                "division": request.form.get('division').strip().upper()
            })

        user = User(
            username=request.form['username'],
            password_hash=generate_password_hash(request.form['password']),
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
        flash(f"Class {cls_obj['class_name']} added!", "success")

    db.session.commit()
    return redirect('/teacher/dashboard')


@routes.route('/teacher/create-assignment', methods=['GET', 'POST'])
def create_assignment():
    if session.get('role') != 'teacher': return redirect('/login')

    # Ghost User Fix
    teacher = User.query.get(session.get('user_id'))
    if not teacher:
        session.clear()
        flash("Session expired.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        try:
            file = request.files.get('questionnaire_file')
            key_text = request.form.get('ai_generated_key')

            if not request.form.get('class_name'):
                flash("Class name is required", "danger")
                return redirect('/teacher/create-assignment')

            file_data = file.read() if file else None

            new_assign = Assignment(
                title=request.form['title'],
                class_name=request.form['class_name'].strip().upper(),
                division=request.form['division'].strip().upper(),
                subject_name=request.form['subject_name'],
                teacher_name=teacher.username,
                teacher_id=teacher.id,
                answer_key_content=key_text,
                questionnaire_file=file_data,
                questionnaire_filename=secure_filename(file.filename) if file else "unknown.txt"
            )
            db.session.add(new_assign)
            db.session.commit()
            flash("Assignment Created!", "success")
            return redirect('/teacher/assignments')

        except Exception as e:
            print(f"ERROR: {e}")
            flash(f"Error: {e}", "danger")
            return redirect('/teacher/create-assignment')

    return render_template('create_assignment.html')


@routes.route('/teacher/generate-key', methods=['POST'])
def generate_key_api():
    if session.get('role') != 'teacher': return {"error": "Unauthorized"}, 401
    file = request.files.get('file')
    if not file: return {"error": "No file"}, 400

    text = extract_text_from_file(file)
    if not text.strip(): return {"error": "Could not read text from file."}, 400

    return {"key": generate_answer_key(text)}


@routes.route('/teacher/assignments')
def view_assignments():
    if session.get('role') != 'teacher': return redirect('/login')
    assignments = Assignment.query.filter_by(teacher_id=session['user_id']).all()
    return render_template('view_assignments.html', assignments=assignments)


@routes.route('/teacher/assignments/<int:assignment_id>/edit', methods=['GET', 'POST'])
def edit_assignment(assignment_id):
    if session.get('role') != 'teacher': return redirect('/login')
    assignment = Assignment.query.get_or_404(assignment_id)
    if request.method == 'POST':
        assignment.title = request.form.get('title')
        assignment.class_name = request.form.get('class_name')
        assignment.division = request.form.get('division')
        assignment.subject_name = request.form.get('subject_name')
        db.session.commit()
        flash("Updated!", "success")
        return redirect('/teacher/assignments')
    return render_template('edit_assignment.html', assignment=assignment)


@routes.route('/teacher/assignments/<int:assignment_id>/submissions')
def view_submissions(assignment_id):
    if session.get('role') != 'teacher': return redirect('/login')
    assignment = Assignment.query.get_or_404(assignment_id)
    submissions = Submission.query.filter_by(assignment_id=assignment_id).all()
    return render_template('view_submissions.html', assignment=assignment, submissions=submissions)


@routes.route('/teacher/delete-assignment/<int:id>', methods=['POST'])
def delete_assignment(id):
    if session.get('role') != 'teacher': return redirect('/login')
    assign = Assignment.query.get_or_404(id)
    if assign.teacher_id == session['user_id']:
        db.session.delete(assign)
        db.session.commit()
    return redirect('/teacher/assignments')


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
        date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        for student in students:
            status = request.form.get(f"status_{student.id}")
            if status:
                rec = Attendance(date=date, status=status, student_id=student.id,
                                 teacher_id=teacher.id, class_name=cls, division=div)
                db.session.add(rec)
        db.session.commit()
        flash("Attendance Saved!", "success")
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

        # 1. Read file logic
        filename = file.filename.lower()
        file_data = file.read()

        # 2. Extract Text (Cloud AI or PDF Reader)
        if filename.endswith(('.png', '.jpg', '.jpeg')):
            student_text = extract_text_from_image(file_data)  # Uses Scout
        elif filename.endswith('.pdf'):
            student_text = extract_text_from_file(
                file)  # Uses PyPDF (Re-read required if pointer moved, handled in helper)
            if not student_text:  # Fallback for image-based PDFs could go here
                student_text = ""
        else:
            student_text = file_data.decode('utf-8', errors='ignore')

        # 3. Grade (Uses Maverick)
        score, feedback = compute_score(student_text, assign.answer_key_content)

        sub = Submission(assignment_id=aid, student_id=student.id,
                         submitted_file=file_data, score=score, detailed_feedback=feedback)
        db.session.add(sub)
        db.session.commit()
        flash(f"Graded: {score}%", "success")
        return redirect('/student/dashboard')

    assigns = Assignment.query.filter_by(class_name=student.class_name, division=student.division).all()
    my_subs = {s.assignment_id: s for s in Submission.query.filter_by(student_id=student.id).all()}

    total = Attendance.query.filter_by(student_id=student.id).count()
    present = Attendance.query.filter_by(student_id=student.id, status='Present').count()
    pct = int((present / total) * 100) if total > 0 else 0

    return render_template('student_dashboard.html', student=student, assignments=assigns,
                           submitted_map=my_subs, att_pct=pct, present_days=present, total_days=total)


@routes.route('/student/download/<int:id>')
def download_q(id):
    assign = Assignment.query.get_or_404(id)
    return send_file(BytesIO(assign.questionnaire_file), download_name=assign.questionnaire_filename,
                     as_attachment=True)
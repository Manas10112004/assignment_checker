from flask import Blueprint, render_template, request, redirect, session, flash, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.sql import func
from io import BytesIO
import pypdf
from pdf2image import convert_from_bytes
import uuid
from datetime import datetime
import pyotp
import qrcode
import base64
from cryptography.fernet import Fernet

# --- IMPORTS ---
from app.models import db, User, Assignment, Submission, Attendance, AuditLog, Classroom, Subject
from app.ai_evaluator import compute_score, generate_answer_key, extract_text_from_image

routes = Blueprint('routes', __name__)

# --- CONFIG ---
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)


# --- HELPERS ---
def log_audit(action, details=""):
    try:
        if 'user_id' in session:
            log = AuditLog(
                user_id=session['user_id'],
                username=session.get('username', 'Unknown'),
                action=action,
                ip_address=request.remote_addr,
                details=details
            )
            db.session.add(log)
            db.session.commit()
    except:
        pass


def encrypt_data(text):
    if not text: return None
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text):
    if not encrypted_text: return ""
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return ""


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
                admin = User(username='admin', password_hash=generate_password_hash('admin123'), role='admin',
                             email='admin@eduai.com', is_verified=True)
                db.session.add(admin)
                db.session.commit()
            session['user_id'] = admin.id
            session['role'] = 'admin'
            session['username'] = 'admin'
            log_audit("LOGIN", "Admin Login")
            return redirect('/admin/dashboard')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):

            # 1. CHECK EMAIL VERIFICATION
            if not user.is_verified:
                flash("Please verify your email first. Check your inbox (or console for demo link).", "warning")
                return redirect('/login')

            # 2. MFA CHECK
            if user.mfa_enabled:
                session['pre_mfa_user_id'] = user.id
                return redirect('/mfa/verify')

            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            log_audit("LOGIN", f"User {username} logged in")

            if user.role == 'admin': return redirect('/admin/dashboard')
            if user.role == 'teacher': return redirect('/teacher/dashboard')
            return redirect('/student/dashboard')

        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form.get('username')).first():
            flash('Username taken', 'danger')
            return redirect('/register')

        # Generate Verification Token
        token = str(uuid.uuid4())

        assigned_classes = []
        role = request.form.get('role')
        if role == 'teacher' and request.form.get('class_name'):
            assigned_classes.append({
                "class_name": request.form.get('class_name').strip().upper(),
                "division": request.form.get('division').strip().upper()
            })

        user = User(
            username=request.form.get('username'),
            password_hash=generate_password_hash(request.form.get('password')),
            role=role,
            email=request.form.get('email'),
            phone_number=request.form.get('phone'),
            verification_token=token,
            is_verified=False,  # Must verify first
            class_name=request.form.get('class_name').strip().upper() if role == 'student' and request.form.get(
                'class_name') else None,
            division=request.form.get('division').strip().upper() if role == 'student' and request.form.get(
                'division') else None,
            assigned_classes=assigned_classes
        )
        db.session.add(user)
        db.session.commit()

        # Simulate Sending Email
        verify_link = url_for('routes.verify_email', token=token, _external=True)
        flash(f"DEMO: Verification Link sent to {user.email}: {verify_link}", "info")
        log_audit("REGISTER", f"New user {user.username} registered")

        return redirect('/login')
    return render_template('register.html')


@routes.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash("Email Verified! You can now login.", "success")
        log_audit("EMAIL_VERIFY", f"User {user.username} verified email")
    else:
        flash("Invalid verification link.", "danger")
    return redirect('/login')


@routes.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    if 'user_id' not in session: return redirect('/login')
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        secret = request.form.get('secret')
        code = request.form.get('code')
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            user.mfa_secret = secret
            user.mfa_enabled = True
            db.session.commit()
            flash("MFA Enabled!", "success")
            return redirect('/teacher/dashboard' if user.role == 'teacher' else '/student/dashboard')
        else:
            flash("Invalid Code.", "danger")

    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="EduAI")
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return render_template('mfa_setup.html', secret=secret, qr_code=img_str)


@routes.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pre_mfa_user_id' not in session: return redirect('/login')
    if request.method == 'POST':
        user = User.query.get(session['pre_mfa_user_id'])
        code = request.form.get('code')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            session.pop('pre_mfa_user_id')
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            log_audit("LOGIN_MFA", f"MFA Verified for {user.username}")
            if user.role == 'admin': return redirect('/admin/dashboard')
            if user.role == 'teacher': return redirect('/teacher/dashboard')
            return redirect('/student/dashboard')
        flash("Invalid Code", "danger")
    return render_template('mfa_verify.html')


@routes.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


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


# --- ADMIN ROUTES (Updated for Models) ---
@routes.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin': return redirect('/login')
    users = User.query.order_by(User.id.desc()).all()
    assignments = Assignment.query.order_by(Assignment.id.desc()).all()
    classrooms = Classroom.query.all()

    class_map = {}
    for u in users:
        if u.role == 'student' and u.class_name:
            key = f"{u.class_name} - {u.division}"
            if key not in class_map: class_map[key] = {"students": [], "teachers": []}
            class_map[key]["students"].append(u)
        if u.role == 'teacher' and u.assigned_classes:
            for cls in u.assigned_classes:
                key = f"{cls['class_name']} - {cls['division']}"
                if key not in class_map: class_map[key] = {"students": [], "teachers": []}
                if u not in class_map[key]["teachers"]: class_map[key]["teachers"].append(u)

    stats = {
        "users": len(users),
        "assignments": len(assignments),
        "submissions": Submission.query.count(),
        "avg_score": round(db.session.query(func.avg(Submission.score)).scalar() or 0, 1)
    }
    return render_template('admin_dashboard.html', users=users, assignments=assignments, classrooms=classrooms,
                           class_map=class_map, stats=stats)


@routes.route('/admin/create-class', methods=['POST'])
def create_class():
    if session.get('role') != 'admin': return redirect('/login')
    name = request.form.get('name').strip().upper()
    division = request.form.get('division').strip().upper()
    if not Classroom.query.filter_by(name=name, division=division).first():
        db.session.add(Classroom(name=name, division=division))
        db.session.commit()
        flash(f"Class {name}-{division} created.", "success")
    else:
        flash("Class exists.", "danger")
    return redirect('/admin/dashboard')


@routes.route('/admin/add-subject', methods=['POST'])
def add_subject():
    if session.get('role') != 'admin': return redirect('/login')
    db.session.add(Subject(name=request.form.get('subject_name'), classroom_id=request.form.get('class_id')))
    db.session.commit()
    return redirect('/admin/dashboard')


@routes.route('/admin/create-user', methods=['POST'])
def admin_create_user():
    if session.get('role') != 'admin': return redirect('/login')
    username = request.form.get('username')
    if User.query.filter_by(username=username).first():
        flash("Username exists.", "danger")
        return redirect('/admin/dashboard')

    role = request.form.get('role')
    cls = request.form.get('class_name')
    div = request.form.get('division')
    assigned_classes = [
        {"class_name": cls.strip().upper(), "division": div.strip().upper()}] if role == 'teacher' and cls else []

    new_user = User(
        username=username,
        password_hash=generate_password_hash(request.form.get('password')),
        role=role,
        email=f"{username}@edu.com",  # Placeholder for admin-created users
        is_verified=True,
        class_name=cls.strip().upper() if role == 'student' and cls else None,
        division=div.strip().upper() if role == 'student' and div else None,
        assigned_classes=assigned_classes
    )
    db.session.add(new_user)
    db.session.commit()
    flash("User created!", "success")
    return redirect('/admin/dashboard')


@routes.route('/admin/delete-user/<int:id>', methods=['POST'])
def delete_user(id):
    if session.get('role') != 'admin': return redirect('/login')
    user = User.query.get_or_404(id)
    if user.id != session['user_id']:
        db.session.delete(user)
        db.session.commit()
        flash("Deleted.", "success")
    return redirect('/admin/dashboard')


@routes.route('/admin/edit-user/<int:id>', methods=['POST'])
def edit_user(id):
    if session.get('role') != 'admin': return redirect('/login')
    user = User.query.get_or_404(id)
    user.username = request.form.get('username')
    user.class_name = request.form.get('class_name')
    user.division = request.form.get('division')
    if request.form.get('new_password'): user.password_hash = generate_password_hash(request.form.get('new_password'))
    db.session.commit()
    flash("Updated.", "success")
    return redirect('/admin/dashboard')


@routes.route('/admin/delete-assignment/<int:id>', methods=['POST'])
def admin_delete_assignment(id):
    if session.get('role') != 'admin': return redirect('/login')
    db.session.delete(Assignment.query.get_or_404(id))
    db.session.commit()
    return redirect('/admin/dashboard')


# --- TEACHER ROUTES (Updated) ---
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
            encrypted_key = encrypt_data(key_text)

            new_assign = Assignment(
                title=request.form.get('title'),
                class_name=request.form.get('class_name').strip().upper(),
                division=request.form.get('division').strip().upper(),
                subject_name=request.form.get('subject_name'),
                teacher_name=teacher.username,
                teacher_id=teacher.id,
                answer_key_content=encrypted_key,
                questionnaire_file=file.read() if file else None,
                questionnaire_filename=secure_filename(file.filename) if file else "unknown.txt",
                atype=request.form.get('atype', 'assignment'),
                duration_minutes=int(request.form.get('duration', 0))
            )
            db.session.add(new_assign)
            db.session.commit()
            flash("Created!", "success")
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


@routes.route('/teacher/attendance', methods=['GET', 'POST'])
def teacher_attendance():
    if session.get('role') != 'teacher': return redirect('/login')
    teacher = User.query.get(session['user_id'])
    cls = request.args.get('class_name')
    div = request.args.get('div')
    students = []
    if cls and div: students = User.query.filter_by(role='student', class_name=cls, division=div).all()
    if request.method == 'POST':
        date_str = request.form.get('date')
        subject_name = request.form.get('subject')
        if not date_str or not subject_name:
            flash("Date/Subject required.", "danger")
            return redirect(f"/teacher/attendance?class_name={cls}&div={div}")
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        for student in students:
            status = request.form.get(f"status_{student.id}")
            if status: db.session.add(
                Attendance(date=date, lecture_subject=subject_name, status=status, student_id=student.id,
                           teacher_id=teacher.id, class_name=cls, division=div))
        db.session.commit()
        flash("Saved!", "success")
        return redirect(f"/teacher/attendance?class_name={cls}&div={div}")
    return render_template('teacher_attendance.html', teacher=teacher, students=students, selected_class=cls,
                           selected_div=div, now=datetime.now())


# --- STUDENT ROUTES ---
@routes.route('/student/dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if session.get('role') != 'student': return redirect('/login')
    student = User.query.get(session['user_id'])

    if request.method == 'POST':
        aid = request.form.get('assignment_id')
        file = request.files.get('student_answer')
        tab_switches = request.form.get('tab_switches', 0)

        assign = Assignment.query.get(aid)
        decrypted_key = decrypt_data(assign.answer_key_content)
        student_text = extract_text_from_file(file)
        score, feedback = compute_score(student_text, decrypted_key)

        sub = Submission(assignment_id=aid, student_id=student.id, submitted_file=file.read(), score=score,
                         detailed_feedback=feedback, tab_switches=int(tab_switches),
                         suspicious_activity=(int(tab_switches) > 2))
        db.session.add(sub)
        db.session.commit()
        flash(f"Graded: {score}%", "success")
        return redirect('/student/dashboard')

    all_work = Assignment.query.filter_by(class_name=student.class_name, division=student.division).all()
    assignments = [a for a in all_work if a.atype == 'assignment']
    tests = [a for a in all_work if a.atype == 'test']

    my_subs = {s.assignment_id: s for s in Submission.query.filter_by(student_id=student.id).all()}
    attendance_records = Attendance.query.filter_by(student_id=student.id).order_by(Attendance.date.desc()).all()
    total = len(attendance_records)
    present = len([a for a in attendance_records if a.status == 'Present'])
    pct = int((present / total) * 100) if total > 0 else 0
    return render_template('student_dashboard.html', student=student, assignments=assignments, tests=tests,
                           attendance_records=attendance_records, submitted_map=my_subs, att_pct=pct,
                           present_days=present, total_days=total)


@routes.route('/student/download/<int:id>')
def download_q(id):
    assign = Assignment.query.get_or_404(id)
    return send_file(BytesIO(assign.questionnaire_file), download_name=assign.questionnaire_filename,
                     as_attachment=True)


@routes.route('/api/chat', methods=['POST'])
def chat_api():
    data = request.json
    user_message = data.get('message', '')
    if not user_message: return {"response": "..."}
    from app.ai_evaluator import get_groq_client
    client = get_groq_client()
    if not client: return {"response": "Offline."}
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "system", "content": "Helpful assistant."}, {"role": "user", "content": user_message}],
            model="llama-3.3-70b-versatile")
        return {"response": completion.choices[0].message.content}
    except:
        return {"response": "Error."}
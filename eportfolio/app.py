# [AI生成] Claudeが作成（AI利用記録 #7）
# 自分で変更・追加した箇所には「# [自作]」コメントを付けること。
import os
import secrets
from datetime import date, datetime, timedelta
from uuid import uuid4

import click
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import func, or_
from werkzeug.security import check_password_hash, generate_password_hash

from forms import (ActionForm, DeleteForm, LoginForm, LoginIdChangeForm, LogoutForm,
                   MessageForm, PasswordChangeForm, PasswordResetForm, ProfileForm,
                   RecordFilterForm, RecordForm, ResetRequestForm, SignupForm, WorkForm)
from models import (ATTENDANCE_LABELS, CATEGORY_LABELS, ROLE_STUDENT,
                    ROLE_TEACHER, Message, PasswordResetRequest, PasswordResetToken,
                    Record, User, Work, db, now_jst)
from security import (MIME_TYPES, can_view_student, content_matches_extension,
                      get_extension, login_required, set_security_headers,
                      student_required, teacher_required)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, instance_path=os.path.join(BASE_DIR, "instance"))
os.makedirs(app.instance_path, exist_ok=True)


def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(app.instance_path, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


app.config.update(
    SECRET_KEY=load_secret_key(),
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(app.instance_path, "eportfolio.db")),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", os.path.join(app.instance_path, "uploads")),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_IDLE_TIMEOUT=int(os.environ.get("SESSION_IDLE_TIMEOUT", 30 * 60)),
    SIGNUP_CODE=os.environ.get("SIGNUP_CODE", ""),
    MAX_LOGIN_FAILURES=5,
    LOCK_MINUTES=10,
    PER_PAGE=20,
    RESET_CODE_HOURS=24,
    RESET_CODE_MAX_ATTEMPTS=5,
)

csrf = CSRFProtect(app)
db.init_app(app)

with app.app_context():
    db.create_all()

_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


@app.before_request
def load_user_and_check_timeout():
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return

    now = datetime.now().timestamp()
    last_seen = session.get("last_seen", now)
    if now - last_seen > app.config["SESSION_IDLE_TIMEOUT"]:
        session.clear()
        flash("一定時間操作がなかったため、ログアウトしました。", "warning")
        return redirect(url_for("login"))
    session["last_seen"] = now

    g.user = db.session.get(User, user_id)
    if g.user is None:
        session.clear()


@app.after_request
def add_security_headers(response):
    return set_security_headers(response)


@app.context_processor
def inject_globals():
    unread = 0
    if g.get("user") is not None:
        unread = unread_count_for(g.user)
    return {
        "current_user": g.get("user"),
        "unread_total": unread,
        "CATEGORY_LABELS": CATEGORY_LABELS,
        "ATTENDANCE_LABELS": ATTENDANCE_LABELS,
    }


def get_student_or_404(student_id):
    if not can_view_student(g.user, student_id):
        abort(404)
    student = db.session.get(User, student_id)
    if student is None or not student.is_student:
        abort(404)
    return student


def get_record_or_404(record_id):
    record = db.session.get(Record, record_id)
    if record is None or not can_view_student(g.user, record.student_id):
        abort(404)
    return record


def get_work_or_404(work_id):
    work = db.session.get(Work, work_id)
    if work is None or not can_view_student(g.user, work.student_id):
        abort(404)
    return work


def require_owner(student_id):
    if g.user.id != student_id:
        abort(403)


def unread_filter_for(user):
    if user.is_teacher:
        return [Message.author_id == Message.student_id, Message.read_at.is_(None)]
    return [Message.student_id == user.id, Message.author_id != user.id, Message.read_at.is_(None)]


def unread_count_for(user):
    return Message.query.filter(*unread_filter_for(user)).count()


def mark_read(messages):
    changed = False
    for m in messages:
        if m.read_at is not None:
            continue
        written_by_student = m.author_id == m.student_id
        if (g.user.is_teacher and written_by_student) or (g.user.is_student and not written_by_student):
            m.read_at = now_jst()
            changed = True
    if changed:
        db.session.commit()


def post_message(form, student, record=None, work=None):
    msg = Message(student_id=student.id, author_id=g.user.id, body=form.body.data.strip(),
                  record_id=record.id if record else None, work_id=work.id if work else None)
    db.session.add(msg)
    db.session.commit()
    flash("メッセージを送信しました。", "success")


def find_user_by_login_id(login_id):
    return (User.query.filter_by(username=login_id).first()
            or User.query.filter_by(student_no=login_id).first())


RESET_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def normalize_reset_code(code):
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def login_id_taken(login_id, exclude_user_id=None):
    query = User.query.filter(or_(User.username == login_id, User.student_no == login_id))
    if exclude_user_id is not None:
        query = query.filter(User.id != exclude_user_id)
    return query.first() is not None


def renew_session(user_id):
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["last_seen"] = datetime.now().timestamp()


def save_upload(file_storage):
    ext = get_extension(file_storage.filename)
    if ext is None:
        flash("このファイル形式はアップロードできません。", "danger")
        return None
    if not content_matches_extension(file_storage.stream, ext):
        flash("ファイルの中身が拡張子と一致しません。", "danger")
        return None
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    stored = f"{uuid4().hex}.{ext}"
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
    original = os.path.basename(file_storage.filename.replace("\\", "/"))[:255]
    return stored, original, ext


def delete_upload(file_name):
    if not file_name:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], file_name)
    if os.path.isfile(path):
        os.remove(path)


@app.route("/")
def index():
    if g.user is None:
        return redirect(url_for("login"))
    if g.user.is_teacher:
        return redirect(url_for("teacher_students"))
    return redirect(url_for("karte", student_id=g.user.id))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = find_user_by_login_id(form.username.data.strip())
        now = now_jst()

        if user is not None and user.locked_until and user.locked_until > now:
            flash("ログインに続けて失敗したため、しばらくログインできません。時間をおいて試してください。", "danger")
            return redirect(url_for("login"))

        password_ok = check_password_hash(user.password_hash if user else _DUMMY_HASH,
                                          form.password.data)
        if user is None or not password_ok:
            if user is not None:
                user.failed_login_count += 1
                if user.failed_login_count >= app.config["MAX_LOGIN_FAILURES"]:
                    user.locked_until = now + timedelta(minutes=app.config["LOCK_MINUTES"])
                    user.failed_login_count = 0
                db.session.commit()
            flash("ログインIDまたはパスワードが違います。", "danger")
            return redirect(url_for("login"))

        user.failed_login_count = 0
        user.locked_until = None
        db.session.commit()

        renew_session(user.id)
        flash(f"{user.display_name} さん、ようこそ。", "success")
        return redirect(url_for("index"))
    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        session.clear()
        flash("ログアウトしました。", "success")
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if g.user is not None:
        return redirect(url_for("index"))
    form = SignupForm()
    code_required = bool(app.config["SIGNUP_CODE"])
    if form.validate_on_submit():
        if code_required and not secrets.compare_digest(
                (form.signup_code.data or "").encode(), app.config["SIGNUP_CODE"].encode()):
            flash("登録コードが違います。", "danger")
            return redirect(url_for("signup"))
        if login_id_taken(form.student_no.data):
            flash("この学籍番号はすでに登録されています。", "danger")
            return redirect(url_for("signup"))
        user = User(username=form.student_no.data, display_name=form.display_name.data,
                    student_no=form.student_no.data, role=ROLE_STUDENT,
                    password_hash=generate_password_hash(form.password.data))
        db.session.add(user)
        db.session.commit()
        flash("登録しました。ログインしてください。", "success")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form, code_required=code_required)


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if not check_password_hash(g.user.password_hash, form.current.data):
            flash("現在のパスワードが違います。", "danger")
            return redirect(url_for("change_password"))
        g.user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        renew_session(g.user.id)
        flash("パスワードを変更しました。", "success")
        return redirect(url_for("index"))
    return render_template("password.html", form=form)


@app.route("/password/forgot", methods=["GET", "POST"])
def password_forgot():
    if g.user is not None:
        return redirect(url_for("change_password"))
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = find_user_by_login_id(form.login_id.data)
        if user is not None and user.is_student and user.pending_reset_request is None:
            db.session.add(PasswordResetRequest(user_id=user.id))
            db.session.commit()
        flash("リセットを依頼しました。教員から再設定コードを受け取ったら、"
              "「再設定コードを持っている場合」から新しいパスワードを設定してください。", "info")
        return redirect(url_for("password_forgot"))
    return render_template("password_forgot.html", form=form)


@app.route("/password/reset", methods=["GET", "POST"])
def password_reset():
    if g.user is not None:
        return redirect(url_for("change_password"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = find_user_by_login_id(form.login_id.data)
        token = None
        if user is not None:
            token = (PasswordResetToken.query
                     .filter(PasswordResetToken.user_id == user.id,
                             PasswordResetToken.used_at.is_(None),
                             PasswordResetToken.expires_at > now_jst())
                     .order_by(PasswordResetToken.id.desc()).first())
        code = normalize_reset_code(form.code.data)
        if token is None or not check_password_hash(token.code_hash, code):
            if token is not None:
                token.failed_attempts += 1
                if token.failed_attempts >= app.config["RESET_CODE_MAX_ATTEMPTS"]:
                    token.used_at = now_jst()
                db.session.commit()
            flash("学籍番号（ログインID）または再設定コードが違うか、コードの有効期限が切れています。", "danger")
            return redirect(url_for("password_reset"))

        user.password_hash = generate_password_hash(form.password.data)
        user.failed_login_count = 0
        user.locked_until = None
        token.used_at = now_jst()
        db.session.commit()
        flash("パスワードを再設定しました。新しいパスワードでログインしてください。", "success")
        return redirect(url_for("login"))
    return render_template("password_reset.html", form=form)


@app.route("/teacher/students/<int:student_id>/reset-code", methods=["POST"])
@teacher_required
def issue_reset_code(student_id):
    student = get_student_or_404(student_id)
    if not ActionForm().validate_on_submit():
        abort(400)
    now = now_jst()
    PasswordResetToken.query.filter_by(user_id=student.id, used_at=None).update({"used_at": now})
    code = "".join(secrets.choice(RESET_CODE_ALPHABET) for _ in range(8))
    token = PasswordResetToken(user_id=student.id, created_by_id=g.user.id,
                               code_hash=generate_password_hash(code),
                               expires_at=now + timedelta(hours=app.config["RESET_CODE_HOURS"]))
    db.session.add(token)
    PasswordResetRequest.query.filter_by(user_id=student.id, resolved_at=None).update({"resolved_at": now})
    db.session.commit()
    return render_template("reset_code_issued.html", student=student,
                           code=f"{code[:4]}-{code[4:]}", expires_at=token.expires_at)


@app.route("/account/login-id", methods=["GET", "POST"])
@login_required
def change_login_id():
    form = LoginIdChangeForm()
    if request.method == "GET":
        form.new_username.data = g.user.username
    if form.validate_on_submit():
        if not check_password_hash(g.user.password_hash, form.current.data):
            flash("現在のパスワードが違います。", "danger")
            return redirect(url_for("change_login_id"))
        new_id = form.new_username.data
        if new_id == g.user.username:
            flash("今と同じログインIDです。", "info")
            return redirect(url_for("change_login_id"))
        if login_id_taken(new_id, exclude_user_id=g.user.id):
            flash("このログインID（学籍番号）はすでに使われています。", "danger")
            return redirect(url_for("change_login_id"))
        g.user.username = new_id
        if g.user.is_student:
            g.user.student_no = new_id
        db.session.commit()
        renew_session(g.user.id)
        flash(f"ログインIDを {new_id} に変更しました。次回からはこのIDでログインしてください。", "success")
        return redirect(url_for("index"))
    return render_template("login_id.html", form=form)


@app.route("/karte/<int:student_id>")
@login_required
def karte(student_id):
    student = get_student_or_404(student_id)
    filter_form = RecordFilterForm(request.args)
    page = request.args.get("page", 1, type=int)

    query = Record.query.filter_by(student_id=student.id)
    if filter_form.validate():
        if filter_form.category.data:
            query = query.filter(Record.category == filter_form.category.data)
        if filter_form.q.data:
            like = f"%{filter_form.q.data}%"
            query = query.filter(or_(Record.title.like(like), Record.body.like(like),
                                     Record.course.like(like)))
    pagination = (query.order_by(Record.record_date.desc(), Record.id.desc())
                  .paginate(page=page, per_page=app.config["PER_PAGE"], error_out=False))

    stats = dict(db.session.query(Record.category, func.count(Record.id))
                 .filter(Record.student_id == student.id).group_by(Record.category).all())
    attendance = dict(db.session.query(Record.attendance_status, func.count(Record.id))
                      .filter(Record.student_id == student.id, Record.category == "attendance")
                      .group_by(Record.attendance_status).all())
    return render_template("karte.html", student=student, tab="records",
                           pagination=pagination, filter_form=filter_form,
                           stats=stats, attendance=attendance, delete_form=DeleteForm())


@app.route("/karte/<int:student_id>/profile", methods=["GET", "POST"])
@student_required
def edit_profile(student_id):
    require_owner(student_id)
    form = ProfileForm(obj=g.user)
    if form.validate_on_submit():
        g.user.display_name = form.display_name.data
        for field in ("grade", "pj_assignment", "bio"):
            setattr(g.user, field, getattr(form, field).data or None)
        db.session.commit()
        flash("プロフィールを保存しました。", "success")
        return redirect(url_for("karte", student_id=g.user.id))
    return render_template("profile_form.html", form=form)


@app.route("/records/new", methods=["GET", "POST"])
@student_required
def record_new():
    form = RecordForm()
    if request.method == "GET":
        form.record_date.data = date.today()
        if request.args.get("category") in CATEGORY_LABELS:
            form.category.data = request.args["category"]
    if form.validate_on_submit():
        record = Record(student_id=g.user.id)
        form.copy_to(record)
        db.session.add(record)
        db.session.commit()
        flash("記録を追加しました。", "success")
        return redirect(url_for("karte", student_id=g.user.id))
    return render_template("record_form.html", form=form, record=None)


@app.route("/records/<int:record_id>", methods=["GET", "POST"])
@login_required
def record_detail(record_id):
    record = get_record_or_404(record_id)
    form = MessageForm()
    if form.validate_on_submit():
        post_message(form, record.student, record=record)
        return redirect(url_for("record_detail", record_id=record.id))
    messages = (Message.query.filter_by(record_id=record.id)
                .order_by(Message.created_at, Message.id).all())
    mark_read(messages)
    return render_template("record_detail.html", record=record, student=record.student,
                           messages=messages, form=form, delete_form=DeleteForm())


@app.route("/records/<int:record_id>/edit", methods=["GET", "POST"])
@student_required
def record_edit(record_id):
    record = get_record_or_404(record_id)
    require_owner(record.student_id)
    form = RecordForm()
    if request.method == "GET":
        form.copy_from(record)
    if form.validate_on_submit():
        form.copy_to(record)
        db.session.commit()
        flash("記録を更新しました。", "success")
        return redirect(url_for("record_detail", record_id=record.id))
    return render_template("record_form.html", form=form, record=record)


@app.route("/records/<int:record_id>/delete", methods=["POST"])
@student_required
def record_delete(record_id):
    record = get_record_or_404(record_id)
    require_owner(record.student_id)
    if DeleteForm().validate_on_submit():
        db.session.delete(record)
        db.session.commit()
        flash("記録を削除しました。", "warning")
    return redirect(url_for("karte", student_id=g.user.id))


@app.route("/karte/<int:student_id>/works")
@login_required
def works(student_id):
    student = get_student_or_404(student_id)
    work_list = (Work.query.filter_by(student_id=student.id)
                 .order_by(Work.created_at.desc(), Work.id.desc()).all())
    return render_template("works.html", student=student, tab="works", works=work_list)


@app.route("/works/new", methods=["GET", "POST"])
@student_required
def work_new():
    form = WorkForm()
    if form.validate_on_submit():
        file = form.file.data
        has_file = file is not None and getattr(file, "filename", "")
        if not has_file and not form.external_url.data:
            flash("ファイルか外部リンクのどちらかを登録してください。", "danger")
            return render_template("work_form.html", form=form, work=None)
        work = Work(student_id=g.user.id, title=form.title.data,
                    description=form.description.data or None,
                    external_url=form.external_url.data or None)
        if has_file:
            saved = save_upload(file)
            if saved is None:
                return render_template("work_form.html", form=form, work=None)
            work.file_name, work.original_name, work.file_type = saved
        db.session.add(work)
        db.session.commit()
        flash("作品を登録しました。", "success")
        return redirect(url_for("work_detail", work_id=work.id))
    return render_template("work_form.html", form=form, work=None)


@app.route("/works/<int:work_id>", methods=["GET", "POST"])
@login_required
def work_detail(work_id):
    work = get_work_or_404(work_id)
    form = MessageForm()
    if form.validate_on_submit():
        post_message(form, work.student, work=work)
        return redirect(url_for("work_detail", work_id=work.id))
    messages = (Message.query.filter_by(work_id=work.id)
                .order_by(Message.created_at, Message.id).all())
    mark_read(messages)
    return render_template("work_detail.html", work=work, student=work.student,
                           messages=messages, form=form, delete_form=DeleteForm())


@app.route("/works/<int:work_id>/edit", methods=["GET", "POST"])
@student_required
def work_edit(work_id):
    work = get_work_or_404(work_id)
    require_owner(work.student_id)
    form = WorkForm(obj=work) if request.method == "GET" else WorkForm()
    if form.validate_on_submit():
        file = form.file.data
        has_file = file is not None and getattr(file, "filename", "")
        if not has_file and not form.external_url.data and not work.file_name:
            flash("ファイルか外部リンクのどちらかを登録してください。", "danger")
            return render_template("work_form.html", form=form, work=work)
        if has_file:
            saved = save_upload(file)
            if saved is None:
                return render_template("work_form.html", form=form, work=work)
            delete_upload(work.file_name)
            work.file_name, work.original_name, work.file_type = saved
        work.title = form.title.data
        work.description = form.description.data or None
        work.external_url = form.external_url.data or None
        db.session.commit()
        flash("作品を更新しました。", "success")
        return redirect(url_for("work_detail", work_id=work.id))
    return render_template("work_form.html", form=form, work=work)


@app.route("/works/<int:work_id>/delete", methods=["POST"])
@student_required
def work_delete(work_id):
    work = get_work_or_404(work_id)
    require_owner(work.student_id)
    if DeleteForm().validate_on_submit():
        file_name = work.file_name
        db.session.delete(work)
        db.session.commit()
        delete_upload(file_name)
        flash("作品を削除しました。", "warning")
    return redirect(url_for("works", student_id=g.user.id))


@app.route("/works/<int:work_id>/file")
@login_required
def work_file(work_id):
    work = get_work_or_404(work_id)
    if not work.file_name:
        abort(404)
    response = send_from_directory(app.config["UPLOAD_FOLDER"], work.file_name,
                                   mimetype=MIME_TYPES.get(work.file_type),
                                   as_attachment=request.args.get("download") == "1",
                                   download_name=work.original_name or work.file_name)
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return response


@app.route("/karte/<int:student_id>/messages", methods=["GET", "POST"])
@login_required
def messages(student_id):
    student = get_student_or_404(student_id)
    form = MessageForm()
    if form.validate_on_submit():
        post_message(form, student)
        return redirect(url_for("messages", student_id=student.id))
    thread = (Message.query.filter_by(student_id=student.id)
              .order_by(Message.created_at, Message.id).all())
    mark_read(thread)
    return render_template("messages.html", student=student, tab="messages",
                           messages=thread, form=form)


@app.route("/teacher/students")
@teacher_required
def teacher_students():
    q = (request.args.get("q") or "").strip()[:100]
    pj = (request.args.get("pj") or "").strip()[:100]

    query = User.query.filter_by(role=ROLE_STUDENT)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.display_name.like(like), User.username.like(like),
                                 User.student_no.like(like)))
    if pj:
        query = query.filter(User.pj_assignment == pj)
    students = query.order_by(User.student_no, User.username).all()

    record_stats = {sid: (cnt, last) for sid, cnt, last in
                    db.session.query(Record.student_id, func.count(Record.id),
                                     func.max(Record.record_date))
                    .group_by(Record.student_id).all()}
    work_counts = dict(db.session.query(Work.student_id, func.count(Work.id))
                       .group_by(Work.student_id).all())
    unread = dict(db.session.query(Message.student_id, func.count(Message.id))
                  .filter(*unread_filter_for(g.user)).group_by(Message.student_id).all())
    reset_requests = {row[0] for row in db.session.query(PasswordResetRequest.user_id)
                      .filter(PasswordResetRequest.resolved_at.is_(None)).all()}
    pj_list = [row[0] for row in db.session.query(User.pj_assignment)
               .filter(User.role == ROLE_STUDENT, User.pj_assignment.isnot(None))
               .distinct().order_by(User.pj_assignment).all()]
    return render_template("teacher_students.html", students=students, q=q, pj=pj,
                           pj_list=pj_list, record_stats=record_stats,
                           work_counts=work_counts, unread=unread, reset_requests=reset_requests)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("フォームの有効期限が切れたか、不正な送信です。もう一度操作してください。", "danger")
    return render_template("errors/error.html", code=400, message="不正なリクエストです。"), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/error.html", code=403, message="この操作は許可されていません。"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/error.html", code=404, message="ページが見つかりません。"), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("errors/error.html", code=413,
                           message="ファイルが大きすぎます（10MBまで）。"), 413


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return render_template("errors/error.html", code=500, message="サーバーでエラーが発生しました。"), 500


@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    click.echo("データベースを初期化しました。")


@app.cli.command("create-user")
@click.option("--username", prompt="ログインID（学生なら学籍番号）")
@click.option("--name", "display_name", prompt="氏名")
@click.option("--role", type=click.Choice([ROLE_TEACHER, ROLE_STUDENT]), default=ROLE_TEACHER,
              show_default=True)
@click.password_option("--password", prompt="パスワード")
def create_user_command(username, display_name, role, password):
    db.create_all()
    if len(password) < 8:
        raise click.ClickException("パスワードは8文字以上にしてください。")
    if login_id_taken(username):
        raise click.ClickException("このログインIDはすでに使われています。")
    db.session.add(User(username=username, display_name=display_name, role=role,
                        student_no=username if role == ROLE_STUDENT else None,
                        password_hash=generate_password_hash(password)))
    db.session.commit()
    click.echo(f"{role} アカウント {username} を作成しました。")


@app.cli.command("reset-password")
@click.option("--username", prompt="ログインID（学生なら学籍番号）")
@click.password_option("--password", prompt="新しいパスワード")
def reset_password_command(username, password):
    if len(password) < 8:
        raise click.ClickException("パスワードは8文字以上にしてください。")
    user = find_user_by_login_id(username)
    if user is None:
        raise click.ClickException("そのログインIDのユーザーはいません。")
    user.password_hash = generate_password_hash(password)
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()
    click.echo(f"{user.username} のパスワードを再設定しました。")


@app.cli.command("seed-demo")
def seed_demo_command():
    db.create_all()
    if User.query.first():
        raise click.ClickException("すでにデータがあります。空のデータベースで実行してください。")
    pw = generate_password_hash("password123")
    teacher = User(username="teacher", display_name="武蔵野 先生", role=ROLE_TEACHER, password_hash=pw)
    s1 = User(username="s2522001", display_name="山田 太郎", role=ROLE_STUDENT, password_hash=pw,
              student_no="s2522001", grade="2年", pj_assignment="地域活性化PJ",
              bio="Webアプリ開発に興味があります。")
    s2 = User(username="s2522002", display_name="佐藤 花子", role=ROLE_STUDENT, password_hash=pw,
              student_no="s2522002", grade="2年", pj_assignment="AI活用PJ")
    db.session.add_all([teacher, s1, s2])
    db.session.flush()
    today = date.today()
    db.session.add_all([
        Record(student_id=s1.id, category="attendance", record_date=today - timedelta(days=7),
               course="Webアプリケーション開発", title="第9回 ORマッピング", attendance_status="present"),
        Record(student_id=s1.id, category="slack", record_date=today - timedelta(days=7),
               course="#web-app-dev", title="課題の質問",
               body="dataaccess_orm.py の search_order_lines が無くてエラーになったので質問しました。"),
        Record(student_id=s1.id, category="pj", record_date=today - timedelta(days=3),
               course="地域活性化PJ", title="キックオフミーティング",
               body="商店街の方とヒアリングの日程を決めた。"),
        Record(student_id=s1.id, category="activity", record_date=today - timedelta(days=1),
               title="ハッカソン参加", body="チームでフロントエンドを担当した。"),
        Work(student_id=s1.id, title="オンラインショップ（授業課題）",
             description="Flask で作ったオンラインショップ。", external_url="https://github.com/"),
    ])
    db.session.flush()
    db.session.add_all([
        Message(student_id=s1.id, author_id=teacher.id, body="ハッカソンお疲れさまでした。担当した画面を作品に登録してみてください。"),
        Message(student_id=s1.id, author_id=s1.id, body="ありがとうございます。今週中に登録します。"),
    ])
    db.session.commit()
    click.echo("サンプルデータを登録しました（teacher / s2522001 / s2522002、パスワード password123）。")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")

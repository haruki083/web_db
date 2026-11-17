from datetime import datetime, timedelta, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

JST = timezone(timedelta(hours=9))


def now_jst():
    return datetime.now(JST).replace(tzinfo=None)


ROLE_STUDENT = "student"
ROLE_TEACHER = "teacher"

CATEGORIES = [
    ("attendance", "出席"),
    ("slack", "授業チャンネルへの書き込み"),
    ("pj", "未来創造PJ"),
    ("activity", "活動の様子"),
    ("other", "その他"),
]
CATEGORY_LABELS = dict(CATEGORIES)

ATTENDANCE_STATUSES = [
    ("present", "出席"),
    ("late", "遅刻"),
    ("absent", "欠席"),
    ("excused", "公欠"),
]
ATTENDANCE_LABELS = dict(ATTENDANCE_STATUSES)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), nullable=False, default=ROLE_STUDENT)

    student_no = db.Column(db.String(32))
    grade = db.Column(db.String(16))
    pj_assignment = db.Column(db.String(100))
    bio = db.Column(db.Text)

    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, nullable=False, default=now_jst)

    records = db.relationship("Record", back_populates="student",
                              cascade="all, delete-orphan",
                              foreign_keys="Record.student_id")
    works = db.relationship("Work", back_populates="student",
                            cascade="all, delete-orphan",
                            foreign_keys="Work.student_id")

    @property
    def is_teacher(self):
        return self.role == ROLE_TEACHER

    @property
    def is_student(self):
        return self.role == ROLE_STUDENT

    @property
    def pending_reset_request(self):
        return (PasswordResetRequest.query
                .filter_by(user_id=self.id, resolved_at=None)
                .order_by(PasswordResetRequest.id.desc()).first())

    def __repr__(self):
        return f"<User {self.id}:{self.username}>"


class Record(db.Model):
    __tablename__ = "records"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    category = db.Column(db.String(16), nullable=False, index=True)
    record_date = db.Column(db.Date, nullable=False, index=True)
    course = db.Column(db.String(100))
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text)
    attendance_status = db.Column(db.String(16))
    link_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, nullable=False, default=now_jst)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_jst, onupdate=now_jst)

    student = db.relationship("User", back_populates="records", foreign_keys=[student_id])
    messages = db.relationship("Message", back_populates="record",
                               cascade="all, delete-orphan")

    @property
    def category_label(self):
        return CATEGORY_LABELS.get(self.category, self.category)

    @property
    def attendance_label(self):
        return ATTENDANCE_LABELS.get(self.attendance_status, "")

    def __repr__(self):
        return f"<Record {self.id}:{self.category}>"


class Work(db.Model):
    __tablename__ = "works"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    external_url = db.Column(db.String(500))
    file_name = db.Column(db.String(100))
    original_name = db.Column(db.String(255))
    file_type = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, nullable=False, default=now_jst)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_jst, onupdate=now_jst)

    student = db.relationship("User", back_populates="works", foreign_keys=[student_id])
    messages = db.relationship("Message", back_populates="work",
                               cascade="all, delete-orphan")

    @property
    def is_image(self):
        return self.file_type in {"png", "jpg", "jpeg", "gif", "webp"}

    def __repr__(self):
        return f"<Work {self.id}:{self.title}>"


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                          nullable=False)
    record_id = db.Column(db.Integer, db.ForeignKey("records.id", ondelete="CASCADE"))
    work_id = db.Column(db.Integer, db.ForeignKey("works.id", ondelete="CASCADE"))
    body = db.Column(db.Text, nullable=False)
    read_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=now_jst)

    author = db.relationship("User", foreign_keys=[author_id])
    student = db.relationship("User", foreign_keys=[student_id])
    record = db.relationship("Record", back_populates="messages")
    work = db.relationship("Work", back_populates="messages")

    def __repr__(self):
        return f"<Message {self.id}>"


class PasswordResetRequest(db.Model):
    __tablename__ = "password_reset_requests"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_jst)
    resolved_at = db.Column(db.DateTime)

    user = db.relationship("User", foreign_keys=[user_id])


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    expires_at = db.Column(db.DateTime, nullable=False)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=now_jst)

    user = db.relationship("User", foreign_keys=[user_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])


# [AI生成] Claudeが作成（AI利用記録 #7）
# 自分で変更・追加した箇所には「# [自作]」コメントを付けること。
# tests/test_app.py
# 実行方法（eportfolio フォルダで）:  python -m pytest -q
import io
import os
import sys
import tempfile
from datetime import date

import pytest

_TMP = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_TMP, "test.db")
os.environ["UPLOAD_FOLDER"] = os.path.join(_TMP, "uploads")
os.environ["SECRET_KEY"] = "test-secret-key"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash  # noqa: E402

from app import app  # noqa: E402
from models import (Message, PasswordResetRequest, PasswordResetToken,  # noqa: E402
                    Record, User, Work, db)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SIGNUP_CODE="")
    with app.app_context():
        db.drop_all()
        db.create_all()
        pw = generate_password_hash("password123")
        db.session.add_all([
            User(username="teacher", display_name="先生", role="teacher", password_hash=pw),
            User(username="alice", display_name="アリス", role="student", password_hash=pw),
            User(username="bob", display_name="ボブ", role="student", password_hash=pw),
        ])
        db.session.commit()
    with app.test_client() as c:
        yield c


def uid(username):
    with app.app_context():
        return User.query.filter_by(username=username).first().id


def login(c, username, password="password123"):
    return c.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def add_record(c, **kw):
    data = {"category": "activity", "record_date": date.today().isoformat(),
            "title": "活動", "body": "内容", "course": "", "attendance_status": "", "link_url": ""}
    data.update(kw)
    return c.post("/records/new", data=data, follow_redirects=True)


# ---------- 認証 ----------
def test_login_and_logout(client):
    res = login(client, "alice")
    assert "アリス さんのカルテ" in res.get_data(as_text=True)
    res = client.post("/logout", follow_redirects=True)
    assert "ログアウトしました" in res.get_data(as_text=True)
    assert client.get("/records/new").status_code == 302


def test_login_error_message_is_generic(client):
    wrong_pw = login(client, "alice", "wrong").get_data(as_text=True)
    no_user = login(client, "nobody", "wrong").get_data(as_text=True)
    assert "ログインIDまたはパスワードが違います" in wrong_pw
    assert "ログインIDまたはパスワードが違います" in no_user


def test_account_lock_after_failures(client):
    for _ in range(5):
        login(client, "alice", "wrong")
    res = login(client, "alice")  # 正しいパスワードでもロック中
    assert "しばらくログインできません" in res.get_data(as_text=True)


def test_signup_password_policy_and_success(client):
    weak = client.post("/signup", data={"student_no": "s2522099", "display_name": "キャロル",
                                        "password": "short", "confirm": "short"})
    assert "8〜128文字" in weak.get_data(as_text=True)
    res = client.post("/signup", data={"student_no": "s2522099", "display_name": "キャロル",
                                       "password": "abcd1234", "confirm": "abcd1234"},
                      follow_redirects=True)
    assert "登録しました" in res.get_data(as_text=True)
    with app.app_context():
        user = User.query.filter_by(username="s2522099").first()
        assert user.role == "student" and user.student_no == "s2522099"
        assert user.password_hash != "abcd1234"


def test_signup_code_required_when_configured(client):
    app.config["SIGNUP_CODE"] = "secret-code"
    data = {"student_no": "s2522098", "display_name": "デイブ", "password": "abcd1234", "confirm": "abcd1234"}
    res = client.post("/signup", data=dict(data, signup_code="wrong"), follow_redirects=True)
    assert "登録コードが違います" in res.get_data(as_text=True)
    res = client.post("/signup", data=dict(data, signup_code="secret-code"), follow_redirects=True)
    assert "登録しました" in res.get_data(as_text=True)


def test_login_with_student_no_after_signup(client):
    client.post("/signup", data={"student_no": "s2522099", "display_name": "キャロル",
                                 "password": "abcd1234", "confirm": "abcd1234"})
    res = login(client, "s2522099", "abcd1234")
    assert "キャロル さんのカルテ" in res.get_data(as_text=True)
    dup = client.post("/logout") and client.post(
        "/signup", data={"student_no": "s2522099", "display_name": "別人",
                         "password": "abcd1234", "confirm": "abcd1234"}, follow_redirects=True)
    assert "すでに登録されています" in dup.get_data(as_text=True)


def test_change_login_id(client):
    login(client, "alice")
    res = client.post("/account/login-id", data={"new_username": "s2522100", "current": "wrong"},
                      follow_redirects=True)
    assert "現在のパスワードが違います" in res.get_data(as_text=True)
    res = client.post("/account/login-id", data={"new_username": "bob", "current": "password123"},
                      follow_redirects=True)
    assert "すでに使われています" in res.get_data(as_text=True)
    res = client.post("/account/login-id", data={"new_username": "bad id!", "current": "password123"},
                      follow_redirects=True)
    assert "半角英数字" in res.get_data(as_text=True)
    res = client.post("/account/login-id", data={"new_username": "s2522100", "current": "password123"},
                      follow_redirects=True)
    assert "s2522100 に変更しました" in res.get_data(as_text=True)
    with app.app_context():
        user = db.session.get(User, uid("s2522100"))
        assert user.student_no == "s2522100"
    client.post("/logout")
    assert "ログインIDまたはパスワードが違います" in login(client, "alice").get_data(as_text=True)
    assert "アリス さんのカルテ" in login(client, "s2522100").get_data(as_text=True)


def test_change_password_then_login(client):
    login(client, "alice")
    res = client.post("/account/password", data={"current": "password123", "password": "newpass99",
                                                 "confirm": "newpass99"}, follow_redirects=True)
    assert "パスワードを変更しました" in res.get_data(as_text=True)
    client.post("/logout")
    assert "ログインIDまたはパスワードが違います" in login(client, "alice").get_data(as_text=True)
    assert "アリス さんのカルテ" in login(client, "alice", "newpass99").get_data(as_text=True)


# ---------- パスワードを忘れたとき ----------
def issue_code(c, student="alice"):
    """教員としてコードを発行し、画面に表示されたコードを返す"""
    login(c, "teacher")
    html = c.post(f"/teacher/students/{uid(student)}/reset-code").get_data(as_text=True)
    c.post("/logout")
    import re
    return re.search(r"([A-Z0-9]{4}-[A-Z0-9]{4})", html).group(1)


def reset(c, login_id, code, password="newpass99"):
    return c.post("/password/reset", data={"login_id": login_id, "code": code,
                                           "password": password, "confirm": password},
                  follow_redirects=True)


def test_forgot_password_full_flow(client):
    assert "パスワードを忘れた場合" in client.get("/login").get_data(as_text=True)
    res = client.post("/password/forgot", data={"login_id": "alice"}, follow_redirects=True)
    assert "リセットを依頼しました" in res.get_data(as_text=True)
    # 存在しないIDでも同じメッセージ（IDの有無を知られないため）
    res = client.post("/password/forgot", data={"login_id": "nobody"}, follow_redirects=True)
    assert "リセットを依頼しました" in res.get_data(as_text=True)
    with app.app_context():
        assert PasswordResetRequest.query.count() == 1

    login(client, "teacher")
    assert "PWリセット依頼" in client.get("/teacher/students").get_data(as_text=True)
    client.post("/logout")

    code = issue_code(client)
    with app.app_context():
        assert PasswordResetRequest.query.filter_by(resolved_at=None).count() == 0
        token = PasswordResetToken.query.first()
        assert code.replace("-", "") not in token.code_hash  # 平文では保存しない

    res = reset(client, "alice", code.lower())  # 小文字でも受け付ける
    assert "パスワードを再設定しました" in res.get_data(as_text=True)
    assert "アリス さんのカルテ" in login(client, "alice", "newpass99").get_data(as_text=True)
    client.post("/logout")
    # 同じコードは2回使えない
    assert "コードの有効期限が切れています" in reset(client, "alice", code, "another99").get_data(as_text=True)


def test_reset_code_wrong_user_and_attempt_limit(client):
    code = issue_code(client, "alice")
    assert "コードの有効期限が切れています" in reset(client, "bob", code).get_data(as_text=True)
    for _ in range(5):
        reset(client, "alice", "WRNG-CODE")
    # 5回間違えたらコードは無効になる
    assert "コードの有効期限が切れています" in reset(client, "alice", code).get_data(as_text=True)


def test_reset_code_expires_and_reissue_invalidates(client):
    first = issue_code(client)
    second = issue_code(client)
    assert "コードの有効期限が切れています" in reset(client, "alice", first).get_data(as_text=True)
    with app.app_context():
        from datetime import datetime
        token = PasswordResetToken.query.filter_by(used_at=None).first()
        token.expires_at = datetime(2000, 1, 1)
        db.session.commit()
    assert "コードの有効期限が切れています" in reset(client, "alice", second).get_data(as_text=True)


def test_only_teacher_can_issue_reset_code(client):
    login(client, "bob")
    assert client.post(f"/teacher/students/{uid('alice')}/reset-code").status_code == 403
    with app.app_context():
        assert PasswordResetToken.query.count() == 0


# ---------- 記録 ----------
def test_student_records_and_attendance_validation(client):
    login(client, "alice")
    res = add_record(client, category="attendance", title="第1回")
    assert "出欠を選択してください" in res.get_data(as_text=True)
    res = add_record(client, category="attendance", title="第1回", attendance_status="present")
    assert "記録を追加しました" in res.get_data(as_text=True)
    res = add_record(client, category="slack", title="質問", link_url="https://example.slack.com/archives/C1/p1")
    page = client.get(f"/karte/{uid('alice')}?category=slack").get_data(as_text=True)
    assert "質問" in page and "第1回" not in page


def test_html_is_escaped(client):
    login(client, "alice")
    add_record(client, title="xss", body="<script>alert(1)</script>")
    with app.app_context():
        rid = Record.query.first().id
    page = client.get(f"/records/{rid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_javascript_url_rejected(client):
    login(client, "alice")
    res = add_record(client, link_url="javascript:alert(1)")
    assert "http:// または https://" in res.get_data(as_text=True)


def test_student_cannot_access_other_karte(client):
    login(client, "alice")
    add_record(client, title="アリスの記録")
    with app.app_context():
        rid = Record.query.first().id
    client.post("/logout")
    login(client, "bob")
    assert client.get(f"/karte/{uid('alice')}").status_code == 404
    assert client.get(f"/records/{rid}").status_code == 404
    assert client.post(f"/records/{rid}/delete").status_code == 404
    with app.app_context():
        assert db.session.get(Record, rid) is not None


def test_teacher_can_view_but_not_edit(client):
    login(client, "alice")
    add_record(client, title="アリスの記録")
    with app.app_context():
        rid = Record.query.first().id
    client.post("/logout")
    login(client, "teacher")
    assert "アリスの記録" in client.get(f"/karte/{uid('alice')}").get_data(as_text=True)
    assert client.get(f"/records/{rid}").status_code == 200
    assert client.get(f"/records/{rid}/edit").status_code == 403
    assert client.get("/records/new").status_code == 403
    assert "アリス" in client.get("/teacher/students").get_data(as_text=True)


def test_student_cannot_open_teacher_pages(client):
    login(client, "alice")
    assert client.get("/teacher/students").status_code == 403


# ---------- 対話 ----------
def test_dialogue_and_unread(client):
    alice = uid("alice")
    login(client, "teacher")
    client.post(f"/karte/{alice}/messages", data={"body": "よく頑張っています"})
    client.post("/logout")

    login(client, "alice")
    with app.app_context():
        assert Message.query.filter(Message.read_at.is_(None)).count() == 1
    page = client.get(f"/karte/{alice}/messages").get_data(as_text=True)
    assert "よく頑張っています" in page
    with app.app_context():
        assert Message.query.filter(Message.read_at.is_(None)).count() == 0
    client.post(f"/karte/{alice}/messages", data={"body": "ありがとうございます"})
    client.post("/logout")

    login(client, "bob")
    assert client.post(f"/karte/{alice}/messages", data={"body": "なりすまし"}).status_code == 404
    with app.app_context():
        assert Message.query.count() == 2


# ---------- 作品 ----------
def test_work_upload_and_access_control(client):
    login(client, "alice")
    res = client.post("/works/new", data={"title": "ポスター", "description": "",
                                          "external_url": "",
                                          "file": (io.BytesIO(PNG), "ポスター.png")},
                      content_type="multipart/form-data", follow_redirects=True)
    assert "作品を登録しました" in res.get_data(as_text=True)
    with app.app_context():
        work = Work.query.first()
        wid = work.id
        assert work.file_name.endswith(".png") and work.original_name == "ポスター.png"
    assert client.get(f"/works/{wid}/file").status_code == 200
    client.post("/logout")

    login(client, "teacher")
    assert client.get(f"/works/{wid}/file").status_code == 200
    client.post("/logout")

    login(client, "bob")
    assert client.get(f"/works/{wid}/file").status_code == 404


def test_fake_image_rejected(client):
    login(client, "alice")
    res = client.post("/works/new", data={"title": "偽物", "external_url": "",
                                          "file": (io.BytesIO(b"<html><script>x</script>"), "a.png")},
                      content_type="multipart/form-data", follow_redirects=True)
    assert "拡張子と一致しません" in res.get_data(as_text=True)
    res = client.post("/works/new", data={"title": "html", "external_url": "",
                                          "file": (io.BytesIO(b"<html>"), "a.html")},
                      content_type="multipart/form-data", follow_redirects=True)
    assert "アップロードできるのは" in res.get_data(as_text=True)
    with app.app_context():
        assert Work.query.count() == 0


def test_work_link_only(client):
    login(client, "alice")
    res = client.post("/works/new", data={"title": "GitHub", "external_url": "https://github.com/"},
                      content_type="multipart/form-data", follow_redirects=True)
    assert "作品を登録しました" in res.get_data(as_text=True)
    res = client.post("/works/new", data={"title": "空"}, content_type="multipart/form-data",
                      follow_redirects=True)
    assert "どちらかを登録してください" in res.get_data(as_text=True)


# ---------- セキュリティ全般 ----------
def test_security_headers(client):
    res = client.get("/login")
    assert "default-src 'self'" in res.headers["Content-Security-Policy"]
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_csrf_is_enforced(client):
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        res = client.post("/login", data={"username": "alice", "password": "password123"})
        assert res.status_code == 400
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


def test_session_idle_timeout(client):
    login(client, "alice")
    with client.session_transaction() as s:
        s["last_seen"] = s["last_seen"] - 31 * 60
    res = client.get("/records/new", follow_redirects=True)
    assert "ログアウトしました" in res.get_data(as_text=True)

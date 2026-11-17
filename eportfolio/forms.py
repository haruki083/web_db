# [AI生成] Claudeが作成（AI利用記録 #7）
# 自分で変更・追加した箇所には「# [自作]」コメントを付けること。
# forms.py
from urllib.parse import urlparse

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import (DateField, PasswordField, SelectField, StringField,
                     SubmitField, TextAreaField)
from wtforms.validators import (DataRequired, EqualTo, Length, Optional,
                                Regexp, ValidationError)

from models import ATTENDANCE_STATUSES, CATEGORIES
from security import ALLOWED_EXTENSIONS


def safe_url(form, field):
    """http/https 以外（javascript: など）のURLを拒否する（XSS対策）"""
    if not field.data:
        return
    parsed = urlparse(field.data.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValidationError("URLは http:// または https:// で始まる形式で入力してください。")


def strip_filter(value):
    return value.strip() if isinstance(value, str) else value


# ---------- 認証 ----------
class LoginForm(FlaskForm):
    username = StringField("学籍番号（教員はログインID）", validators=[
        DataRequired(message="学籍番号（ログインID）を入力してください。"), Length(max=64)])
    password = PasswordField("パスワード", validators=[
        DataRequired(message="パスワードを入力してください。")])
    submit = SubmitField("ログイン")


class LogoutForm(FlaskForm):
    submit = SubmitField("ログアウト")


# 学籍番号（＝ログインID）の入力ルール
LOGIN_ID_RULES = [
    DataRequired(message="学籍番号（ログインID）を入力してください。"),
    Length(min=3, max=32, message="学籍番号（ログインID）は3〜32文字で入力してください。"),
    Regexp(r"^[A-Za-z0-9_.-]+$", message="学籍番号（ログインID）は半角英数字と _ . - のみ使えます。"),
]

PASSWORD_RULES = [
    DataRequired(message="パスワードを入力してください。"),
    Length(min=8, max=128, message="パスワードは8〜128文字で入力してください。"),
    Regexp(r"^(?=.*[A-Za-z])(?=.*\d).+$",
           message="パスワードには英字と数字を両方含めてください。"),
]


class SignupForm(FlaskForm):
    student_no = StringField("学籍番号（ログインIDになります）", filters=[strip_filter],
                             validators=LOGIN_ID_RULES)
    display_name = StringField("氏名", filters=[strip_filter], validators=[
        DataRequired(message="氏名を入力してください。"), Length(max=64)])
    password = PasswordField("パスワード", validators=PASSWORD_RULES)
    confirm = PasswordField("パスワード（確認）", validators=[
        DataRequired(message="確認用パスワードを入力してください。"),
        EqualTo("password", message="パスワードが一致しません。")])
    signup_code = PasswordField("登録コード（教員から配布）", validators=[Optional(), Length(max=128)])
    submit = SubmitField("登録")


class PasswordChangeForm(FlaskForm):
    current = PasswordField("現在のパスワード", validators=[
        DataRequired(message="現在のパスワードを入力してください。")])
    password = PasswordField("新しいパスワード", validators=PASSWORD_RULES)
    confirm = PasswordField("新しいパスワード（確認）", validators=[
        DataRequired(message="確認用パスワードを入力してください。"),
        EqualTo("password", message="パスワードが一致しません。")])
    submit = SubmitField("変更する")


class LoginIdChangeForm(FlaskForm):
    """学籍番号（ログインID）の変更。本人確認のため現在のパスワードも求める"""
    new_username = StringField("新しい学籍番号（ログインID）", filters=[strip_filter],
                               validators=LOGIN_ID_RULES)
    current = PasswordField("現在のパスワード", validators=[
        DataRequired(message="現在のパスワードを入力してください。")])
    submit = SubmitField("変更する")


class ResetRequestForm(FlaskForm):
    """ログイン画面から：教員にパスワードリセットを依頼する"""
    login_id = StringField("学籍番号（ログインID）", filters=[strip_filter], validators=[
        DataRequired(message="学籍番号（ログインID）を入力してください。"), Length(max=64)])
    submit = SubmitField("教員にリセットを依頼する")


class PasswordResetForm(FlaskForm):
    """ログイン画面から：教員にもらった再設定コードで新しいパスワードを設定する"""
    login_id = StringField("学籍番号（ログインID）", filters=[strip_filter], validators=[
        DataRequired(message="学籍番号（ログインID）を入力してください。"), Length(max=64)])
    code = StringField("再設定コード", filters=[strip_filter], validators=[
        DataRequired(message="教員から受け取った再設定コードを入力してください。"), Length(max=32)])
    password = PasswordField("新しいパスワード", validators=PASSWORD_RULES)
    confirm = PasswordField("新しいパスワード（確認）", validators=[
        DataRequired(message="確認用パスワードを入力してください。"),
        EqualTo("password", message="パスワードが一致しません。")])
    submit = SubmitField("パスワードを再設定する")


# ---------- プロフィール ----------
class ProfileForm(FlaskForm):
    display_name = StringField("氏名", filters=[strip_filter], validators=[
        DataRequired(message="氏名を入力してください。"), Length(max=64)])
    grade = StringField("学年", filters=[strip_filter], validators=[Optional(), Length(max=16)])
    pj_assignment = StringField("未来創造PJの配属", filters=[strip_filter],
                                validators=[Optional(), Length(max=100)])
    bio = TextAreaField("自己紹介", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("保存")


# ---------- カルテの記録 ----------
class RecordForm(FlaskForm):
    category = SelectField("種類", choices=CATEGORIES, validators=[DataRequired()])
    record_date = DateField("日付", validators=[DataRequired(message="日付を入力してください。")])
    course = StringField("授業名・チャンネル名・PJ名", filters=[strip_filter],
                         validators=[Optional(), Length(max=100)])
    attendance_status = SelectField("出欠", choices=[("", "（出席の記録のときに選択）")] + ATTENDANCE_STATUSES)
    title = StringField("タイトル", filters=[strip_filter], validators=[
        DataRequired(message="タイトルを入力してください。"), Length(max=200)])
    body = TextAreaField("内容", validators=[Optional(), Length(max=10000)])
    link_url = StringField("関連リンク（Slackのメッセージリンクなど）", filters=[strip_filter],
                           validators=[Optional(), Length(max=500), safe_url])
    submit = SubmitField("保存")

    def validate_attendance_status(self, field):
        if self.category.data == "attendance" and not field.data:
            raise ValidationError("出席の記録では出欠を選択してください。")

    def copy_to(self, record):
        record.category = self.category.data
        record.record_date = self.record_date.data
        record.course = self.course.data or None
        record.title = self.title.data
        record.body = self.body.data or None
        record.link_url = self.link_url.data or None
        record.attendance_status = (self.attendance_status.data
                                    if self.category.data == "attendance" else None)

    def copy_from(self, record):
        self.category.data = record.category
        self.record_date.data = record.record_date
        self.course.data = record.course
        self.title.data = record.title
        self.body.data = record.body
        self.link_url.data = record.link_url
        self.attendance_status.data = record.attendance_status or ""


class RecordFilterForm(FlaskForm):
    """一覧の絞り込み（GET。CSRF不要）"""
    class Meta:
        csrf = False

    category = SelectField("種類", choices=[("", "すべて")] + CATEGORIES, validators=[Optional()])
    q = StringField("キーワード", filters=[strip_filter], validators=[Optional(), Length(max=100)])


# ---------- 作品 ----------
class WorkForm(FlaskForm):
    title = StringField("作品名", filters=[strip_filter], validators=[
        DataRequired(message="作品名を入力してください。"), Length(max=200)])
    description = TextAreaField("説明", validators=[Optional(), Length(max=5000)])
    external_url = StringField("外部リンク（GitHub・YouTube・Webサイトなど）", filters=[strip_filter],
                               validators=[Optional(), Length(max=500), safe_url])
    file = FileField("ファイル（画像・PDF、10MBまで）", validators=[
        FileAllowed(sorted(ALLOWED_EXTENSIONS),
                    message="アップロードできるのは " + ", ".join(sorted(ALLOWED_EXTENSIONS)) + " です。")])
    submit = SubmitField("保存")


# ---------- 対話 ----------
class MessageForm(FlaskForm):
    body = TextAreaField("メッセージ", validators=[
        DataRequired(message="メッセージを入力してください。"),
        Length(max=5000, message="メッセージは5000文字以内で入力してください。")])
    submit = SubmitField("送信")


class ActionForm(FlaskForm):
    """ボタンだけのPOST操作用（CSRFトークンだけを持つ）"""


class DeleteForm(FlaskForm):
    """削除ボタン用（CSRFトークンだけを持つ）"""
    submit = SubmitField("削除")

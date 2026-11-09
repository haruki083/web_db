# ============================================================
# [AI生成] Claudeが作成（AI利用記録 #6）
# 自分で変更・追加した箇所には「# [自作]」コメントを付けること。
#
# 地域活性化ポータルサイト（Flask + PostgreSQL）
#   一般向け : トップ / 店舗一覧・詳細 / 口コミ投稿 / ギャラリー
#   管理者向け: ログイン / 口コミ管理 / 店舗管理 / 写真・動画アップロード
# ============================================================
import os
import secrets
import uuid
from datetime import datetime, time
from functools import wraps
from zoneinfo import ZoneInfo

import psycopg2
import psycopg2.extras
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash

app = Flask(__name__)

# ------------------------------------------------------------
# 設定（パスワードや秘密鍵はコードに書かず、環境変数から読む）
# ------------------------------------------------------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["DATABASE_URL"] = os.environ.get(
    "DATABASE_URL", "dbname=portal user=portal password=portalpass host=localhost")
app.config["REGION_NAME"] = os.environ.get("REGION_NAME", "〇〇町")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # アップロード上限 50MB

# セッションCookieの保護
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JavaScriptから読めないようにする
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # 他サイトからのPOSTにCookieを付けない
# HTTPSで公開するときは環境変数 HTTPS=1 にする（Cookieを暗号化通信のみで送る）
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS") == "1"

# アップロードを許可する拡張子
IMAGE_EXTS = {"jpg", "jpeg", "png", "gif", "webp"}
VIDEO_EXTS = {"mp4", "webm"}


# ------------------------------------------------------------
# データベース接続
# ------------------------------------------------------------
def get_db():
    """1リクエストにつき1つの接続を使い回す"""
    if "db" not in g:
        # 投稿日時を日本時間で記録するため、DBセッションのタイムゾーンを指定
        g.db = psycopg2.connect(app.config["DATABASE_URL"], options="-c timezone=Asia/Tokyo")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), one=False):
    """SELECT用。値は必ず params で渡す（SQLインジェクション対策）"""
    with get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    """INSERT / UPDATE / DELETE 用"""
    db = get_db()
    with db.cursor() as cur:
        cur.execute(sql, params)
    db.commit()


# ------------------------------------------------------------
# セキュリティ: CSRF対策
#   フォームに秘密のトークンを埋め込み、POST時にセッションの値と比較する。
# ------------------------------------------------------------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_globals():
    # テンプレートから {{ csrf_token() }} と {{ region_name }} を使えるようにする
    return {"csrf_token": get_csrf_token, "region_name": app.config["REGION_NAME"]}


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not secrets.compare_digest(sent, session.get("csrf_token", "")):
            abort(400)


# ------------------------------------------------------------
# セキュリティ: レスポンスヘッダ
# ------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"   # MIMEタイプの推測をさせない
    resp.headers["X-Frame-Options"] = "DENY"             # クリックジャッキング対策
    resp.headers["Referrer-Policy"] = "same-origin"
    # 自サイト以外のスクリプト等を読み込ませない（XSSの被害を軽減）
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self'; media-src 'self'; "
        "style-src 'self'; script-src 'self'; frame-ancestors 'none'")
    return resp


# ------------------------------------------------------------
# セキュリティ: 管理者ログインが必要なページ
# ------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "admin_id" not in session:
            flash("ログインしてください。", "error")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------
# 営業中かどうかの判定
# ------------------------------------------------------------
WEEKDAYS = ["月", "火", "水", "木", "金", "土", "日"]
# サーバの時計がUTCでも日本時間で判定する
JST = ZoneInfo("Asia/Tokyo")


def is_open_now(shop, now=None):
    now = now or datetime.now(JST)
    # 定休日（例:「水曜日」「月・火」）に今日の曜日が含まれていれば休み
    if WEEKDAYS[now.weekday()] in shop["closed_days"]:
        return False
    t = now.time()
    open_t, close_t = shop["open_time"], shop["close_time"]
    if open_t <= close_t:                      # 例: 10:00〜19:00
        return open_t <= t < close_t
    return t >= open_t or t < close_t          # 例: 18:00〜翌2:00（日付またぎ）


def add_open_flag(shops):
    for s in shops:
        s["is_open"] = is_open_now(s)
    return shops


# ============================================================
# 一般向けページ
# ============================================================
@app.route("/")
def index():
    shops = add_open_flag(query("SELECT * FROM shops ORDER BY id"))
    media = query("SELECT * FROM media ORDER BY created_at DESC LIMIT 6")
    return render_template("index.html", shops=shops, media=media)


@app.route("/shops")
def shop_list():
    shops = add_open_flag(query("SELECT * FROM shops ORDER BY id"))
    return render_template("shops.html", shops=shops)


@app.route("/shops/<int:shop_id>")
def shop_detail(shop_id):
    shop = query("SELECT * FROM shops WHERE id = %s", (shop_id,), one=True)
    if shop is None:
        abort(404)
    shop["is_open"] = is_open_now(shop)
    # 承認済みの口コミだけを公開する
    reviews = query(
        "SELECT * FROM reviews WHERE shop_id = %s AND status = 'approved' "
        "ORDER BY created_at DESC", (shop_id,))
    return render_template("shop_detail.html", shop=shop, reviews=reviews)


@app.route("/shops/<int:shop_id>/reviews", methods=["POST"])
def post_review(shop_id):
    """口コミ投稿（PRGパターン: POST → 保存 → リダイレクト → GET）"""
    shop = query("SELECT id FROM shops WHERE id = %s", (shop_id,), one=True)
    if shop is None:
        abort(404)

    nickname = request.form.get("nickname", "").strip()
    comment = request.form.get("comment", "").strip()
    rating = request.form.get("rating", "")

    # 入力チェック（サーバ側で必ず行う）
    errors = []
    if not 1 <= len(nickname) <= 30:
        errors.append("ニックネームは1〜30文字で入力してください。")
    if not 1 <= len(comment) <= 1000:
        errors.append("口コミは1〜1000文字で入力してください。")
    if rating not in {"1", "2", "3", "4", "5"}:
        errors.append("評価を1〜5で選んでください。")

    if errors:
        for e in errors:
            flash(e, "error")
    else:
        execute("INSERT INTO reviews (shop_id, nickname, rating, comment) "
                "VALUES (%s, %s, %s, %s)", (shop_id, nickname, int(rating), comment))
        flash("口コミを受け付けました。管理者の確認後に公開されます。", "success")

    # 処理結果に関わらずGETにリダイレクト（再読み込みでの二重投稿を防ぐ）
    return redirect(url_for("shop_detail", shop_id=shop_id))


@app.route("/gallery")
def gallery():
    media = query("SELECT * FROM media ORDER BY created_at DESC")
    return render_template("gallery.html", media=media)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # send_from_directory はフォルダ外へのアクセス（../ など）を拒否する
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ============================================================
# 管理者ページ
# ============================================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        admin = query("SELECT * FROM admins WHERE username = %s", (username,), one=True)
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()  # セッション固定攻撃対策：ログイン時にセッションを作り直す
            session["admin_id"] = admin["id"]
            session["admin_name"] = admin["username"]
            flash("ログインしました。", "success")
            return redirect(url_for("admin_reviews"))
        # IDとパスワードのどちらが違うかは教えない
        flash("ユーザー名またはパスワードが違います。", "error")
        return redirect(url_for("admin_login"))
    return render_template("admin/login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("ログアウトしました。", "success")
    return redirect(url_for("index"))


# ---------- 口コミ管理 ----------
@app.route("/admin/reviews")
@login_required
def admin_reviews():
    status = request.args.get("status", "pending")
    if status not in {"pending", "approved", "hidden"}:
        status = "pending"
    reviews = query(
        "SELECT r.*, s.name AS shop_name FROM reviews r "
        "JOIN shops s ON r.shop_id = s.id WHERE r.status = %s "
        "ORDER BY r.created_at DESC", (status,))
    return render_template("admin/reviews.html", reviews=reviews, status=status)


@app.route("/admin/reviews/<int:review_id>/status", methods=["POST"])
@login_required
def admin_review_status(review_id):
    new_status = request.form.get("status")
    if new_status not in {"approved", "hidden", "pending"}:
        abort(400)
    execute("UPDATE reviews SET status = %s WHERE id = %s", (new_status, review_id))
    flash("口コミの状態を変更しました。", "success")
    return redirect(request.referrer or url_for("admin_reviews"))


@app.route("/admin/reviews/<int:review_id>/delete", methods=["POST"])
@login_required
def admin_review_delete(review_id):
    execute("DELETE FROM reviews WHERE id = %s", (review_id,))
    flash("口コミを削除しました。", "success")
    return redirect(request.referrer or url_for("admin_reviews"))


# ---------- 店舗管理 ----------
def parse_time(value):
    try:
        return datetime.strptime(value, "%H:%M").time()
    except ValueError:
        return None


def read_shop_form():
    """店舗フォームの値を読み取り、(データ, エラー一覧) を返す"""
    f = request.form
    data = {
        "name": f.get("name", "").strip(),
        "category": f.get("category", "").strip(),
        "address": f.get("address", "").strip(),
        "phone": f.get("phone", "").strip(),
        "open_time": parse_time(f.get("open_time", "")),
        "close_time": parse_time(f.get("close_time", "")),
        "closed_days": f.get("closed_days", "").strip(),
        "description": f.get("description", "").strip(),
    }
    errors = []
    if not 1 <= len(data["name"]) <= 100:
        errors.append("店名は1〜100文字で入力してください。")
    if len(data["category"]) > 50 or len(data["address"]) > 200 \
            or len(data["phone"]) > 20 or len(data["closed_days"]) > 50:
        errors.append("入力が長すぎる項目があります。")
    if data["open_time"] is None or data["close_time"] is None:
        errors.append("開店・閉店時間を HH:MM の形式で入力してください。")
    return data, errors


@app.route("/admin/shops")
@login_required
def admin_shops():
    shops = query("SELECT * FROM shops ORDER BY id")
    return render_template("admin/shops.html", shops=shops)


@app.route("/admin/shops/new", methods=["GET", "POST"])
@login_required
def admin_shop_new():
    if request.method == "POST":
        data, errors = read_shop_form()
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin/shop_form.html", shop=request.form)
        execute(
            "INSERT INTO shops (name, category, address, phone, open_time, close_time, "
            "closed_days, description) VALUES (%(name)s, %(category)s, %(address)s, "
            "%(phone)s, %(open_time)s, %(close_time)s, %(closed_days)s, %(description)s)",
            data)
        flash("店舗を登録しました。", "success")
        return redirect(url_for("admin_shops"))
    return render_template("admin/shop_form.html", shop=None)


@app.route("/admin/shops/<int:shop_id>/edit", methods=["GET", "POST"])
@login_required
def admin_shop_edit(shop_id):
    shop = query("SELECT * FROM shops WHERE id = %s", (shop_id,), one=True)
    if shop is None:
        abort(404)
    if request.method == "POST":
        data, errors = read_shop_form()
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin/shop_form.html", shop=request.form, shop_id=shop_id)
        data["id"] = shop_id
        execute(
            "UPDATE shops SET name=%(name)s, category=%(category)s, address=%(address)s, "
            "phone=%(phone)s, open_time=%(open_time)s, close_time=%(close_time)s, "
            "closed_days=%(closed_days)s, description=%(description)s WHERE id=%(id)s",
            data)
        flash("店舗情報を更新しました。", "success")
        return redirect(url_for("admin_shops"))
    # 時刻を HH:MM 形式の文字列にしてフォームに表示
    shop["open_time"] = shop["open_time"].strftime("%H:%M")
    shop["close_time"] = shop["close_time"].strftime("%H:%M")
    return render_template("admin/shop_form.html", shop=shop, shop_id=shop_id)


@app.route("/admin/shops/<int:shop_id>/delete", methods=["POST"])
@login_required
def admin_shop_delete(shop_id):
    execute("DELETE FROM shops WHERE id = %s", (shop_id,))
    flash("店舗を削除しました。", "success")
    return redirect(url_for("admin_shops"))


# ---------- 写真・動画管理 ----------
def detect_media_type(file_storage, ext):
    """
    拡張子だけでなく、ファイル先頭のバイト列（マジックナンバー）も確認する。
    拡張子を偽装した不正ファイルのアップロードを防ぐため。
    """
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if ext in {"jpg", "jpeg"} and head.startswith(b"\xff\xd8\xff"):
        return "image"
    if ext == "png" and head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"
    if ext == "gif" and head[:6] in (b"GIF87a", b"GIF89a"):
        return "image"
    if ext == "webp" and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"
    if ext == "mp4" and head[4:8] == b"ftyp":
        return "video"
    if ext == "webm" and head.startswith(b"\x1a\x45\xdf\xa3"):
        return "video"
    return None


@app.route("/admin/media", methods=["GET", "POST"])
@login_required
def admin_media():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        file = request.files.get("file")

        if not 1 <= len(title) <= 100:
            flash("タイトルは1〜100文字で入力してください。", "error")
            return redirect(url_for("admin_media"))
        if file is None or file.filename == "" or "." not in file.filename:
            flash("ファイルを選択してください。", "error")
            return redirect(url_for("admin_media"))

        ext = file.filename.rsplit(".", 1)[1].lower()
        if ext not in IMAGE_EXTS | VIDEO_EXTS:
            flash("アップロードできるのは jpg/png/gif/webp/mp4/webm のみです。", "error")
            return redirect(url_for("admin_media"))
        media_type = detect_media_type(file, ext)
        if media_type is None:
            flash("ファイルの中身が拡張子と一致しません。", "error")
            return redirect(url_for("admin_media"))

        # 利用者が付けたファイル名は使わず、ランダムな名前で保存する
        filename = f"{uuid.uuid4().hex}.{ext}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        execute("INSERT INTO media (title, description, filename, media_type) "
                "VALUES (%s, %s, %s, %s)", (title, description, filename, media_type))
        flash("アップロードしました。", "success")
        return redirect(url_for("admin_media"))

    media = query("SELECT * FROM media ORDER BY created_at DESC")
    return render_template("admin/media.html", media=media)


@app.route("/admin/media/<int:media_id>/delete", methods=["POST"])
@login_required
def admin_media_delete(media_id):
    m = query("SELECT filename FROM media WHERE id = %s", (media_id,), one=True)
    if m:
        path = os.path.join(app.config["UPLOAD_FOLDER"], m["filename"])
        if os.path.exists(path):
            os.remove(path)
        execute("DELETE FROM media WHERE id = %s", (media_id,))
        flash("削除しました。", "success")
    return redirect(url_for("admin_media"))


# ------------------------------------------------------------
# エラーページ
# ------------------------------------------------------------
@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", message="不正なリクエストです。"), 400


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="ページが見つかりません。"), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", message="ファイルサイズが大きすぎます（上限50MB）。"), 413


if __name__ == "__main__":
    # debug=True は開発時のみ。公開時は必ず False にする
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")

# ============================================================
# [AI生成] Claudeが作成（AI利用記録 #6）
# 管理者アカウントを作成するスクリプト
# 実行: python create_admin.py
# パスワードは画面に表示されないよう getpass で入力し、ハッシュ化して保存する。
# ============================================================
import getpass
import os

import psycopg2
from werkzeug.security import generate_password_hash

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "dbname=portal user=portal password=portalpass host=localhost")

username = input("管理者ユーザー名: ").strip()
password = getpass.getpass("パスワード（8文字以上）: ")
if len(password) < 8:
    raise SystemExit("パスワードは8文字以上にしてください。")

conn = psycopg2.connect(DATABASE_URL)
with conn, conn.cursor() as cur:
    cur.execute("INSERT INTO admins (username, password_hash) VALUES (%s, %s)",
                (username, generate_password_hash(password)))
conn.close()
print(f"管理者 {username} を作成しました。")

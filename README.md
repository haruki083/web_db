# 地域活性化ポータルサイト（Flask + PostgreSQL）

> 生成AI（Claude）の利用について: 初期コードはAIが生成しています（各ファイル先頭に `[AI生成]` と記載）。
> プロンプトと学んだ内容は `docs/AI利用記録.md`、AI以外の参考資料は `docs/参考文献.md` に記録しています。
> 自分で変更・追加した箇所には `# [自作]` コメントを付けています。

## 機能
| 要件 | 実装 |
|---|---|
| 地域の情報発信 | トップページ（`/`） |
| 写真・動画のアップロード | 管理画面 `/admin/media` → ギャラリー `/gallery` |
| 商店情報（開店・閉店時間） | `/shops`, `/shops/<id>`（現在時刻から「営業中」を表示） |
| 口コミ投稿・管理 | 店舗詳細から投稿（PRGパターン）→ 管理者が `/admin/reviews` で公開・非公開・削除 |
| セキュア | 下記「セキュリティ対策」 |

## セットアップ
```bash
pip install -r requirements.txt
# PostgreSQL にユーザーとDBを作成
sudo -u postgres psql -c "CREATE USER portal WITH PASSWORD 'portalpass';" -c "CREATE DATABASE portal OWNER portal;"
psql -h localhost -U portal -d portal -f schema.sql
python create_admin.py
export SECRET_KEY=（ランダムな長い文字列）
export REGION_NAME=〇〇町
flask --app app run
```
DB接続先は環境変数 `DATABASE_URL` で変更できます。

## セキュリティ対策
| 脅威 | 対策 | 場所 |
|---|---|---|
| SQLインジェクション | プレースホルダ（`%s`）で値を渡す | `app.py` の `query()` / `execute()` |
| XSS | Jinja2の自動エスケープ、CSPヘッダ | テンプレート全般、`set_security_headers()` |
| CSRF | 全POSTフォームにトークンを埋め込み検証 | `check_csrf()` |
| パスワード漏洩 | ハッシュ化して保存（werkzeug） | `create_admin.py`, `admin_login()` |
| セッション固定攻撃 | ログイン時に `session.clear()` | `admin_login()` |
| Cookie盗聴・悪用 | HttpOnly / SameSite / Secure 属性 | 設定部 |
| 不正ファイルアップロード | 拡張子＋マジックナンバー確認、ランダムなファイル名、サイズ上限 | `admin_media()`, `detect_media_type()` |
| 権限のない操作 | 管理画面はすべて `@login_required` | 管理者ページ |
| 二重投稿 | PRGパターン | `post_review()` ほか全POST |
| クリックジャッキング | `X-Frame-Options: DENY` | `set_security_headers()` |

## ファイル構成
```
app.py              アプリ本体（ルーティング・DB操作・セキュリティ）
schema.sql          テーブル定義とサンプルデータ
create_admin.py     管理者アカウント作成
templates/          画面（base.html を各ページが継承）
templates/admin/    管理者画面
static/style.css    デザイン
uploads/            アップロードされたファイルの保存先（Git管理外）
docs/               AI利用記録・参考文献
```

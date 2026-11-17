<!-- [AI生成] Claudeが作成（AI利用記録 #11） -->
# eポートフォリオ（カルテ）システム

> 生成AI（Claude）の利用について: コードはAIが生成しています（各ファイル先頭に `[AI生成]` と記載）。
> プロンプトと学んだ内容は `docs/AI利用記録.md`、AI以外の参考資料は `docs/参考文献.md` に記録しています。
> 自分で変更・追加した箇所には `# [自作]` コメントを付けています。

学生の日々の記録（出席・授業チャンネルへの書き込み・未来創造PJ・活動の様子）と作品を個人ごとのカルテに蓄積し、教員が閲覧・対話できるWebアプリケーションです（Flask + Flask-WTF + Flask-SQLAlchemy + SQLite）。

- セットアップ・機能・セキュリティ対策：[eportfolio/README.md](eportfolio/README.md)
- 画面の使い方：[eportfolio/操作マニュアル.md](eportfolio/操作マニュアル.md)

## 起動
```bash
cd eportfolio
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py        # http://127.0.0.1:8080
```

## ファイル構成
```
eportfolio/   アプリ本体（app.py / models.py / forms.py / security.py / templates/ / static/ / tests/）
docs/         AI利用記録・参考文献
```

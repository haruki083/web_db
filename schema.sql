-- ============================================================
-- [AI生成] Claudeが作成（AI利用記録 #6）
-- 地域活性化ポータル テーブル定義（PostgreSQL）
-- 実行: psql -U portal -d portal -f schema.sql
-- ============================================================

DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS media;
DROP TABLE IF EXISTS shops;
DROP TABLE IF EXISTS admins;

-- 管理者（パスワードはハッシュ値のみ保存する）
CREATE TABLE admins (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 商店（開店・閉店時刻を TIME 型で持ち「営業中」を判定できるようにする）
CREATE TABLE shops (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    category     VARCHAR(50)  NOT NULL DEFAULT '',
    address      VARCHAR(200) NOT NULL DEFAULT '',
    phone        VARCHAR(20)  NOT NULL DEFAULT '',
    open_time    TIME         NOT NULL,
    close_time   TIME         NOT NULL,
    closed_days  VARCHAR(50)  NOT NULL DEFAULT '',  -- 例: 「水曜日」
    description  TEXT         NOT NULL DEFAULT '',
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 写真・動画（ファイル本体は uploads/ に保存し、DBにはファイル名だけ記録）
CREATE TABLE media (
    id           SERIAL PRIMARY KEY,
    title        VARCHAR(100) NOT NULL,
    description  TEXT         NOT NULL DEFAULT '',
    filename     VARCHAR(100) NOT NULL UNIQUE,     -- サーバ側で生成した安全なファイル名
    media_type   VARCHAR(10)  NOT NULL CHECK (media_type IN ('image', 'video')),
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 口コミ（一般投稿は status='pending'、管理者が承認すると 'approved' で公開）
CREATE TABLE reviews (
    id           SERIAL PRIMARY KEY,
    shop_id      INTEGER      NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
    nickname     VARCHAR(30)  NOT NULL,
    rating       SMALLINT     NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment      VARCHAR(1000) NOT NULL,
    status       VARCHAR(10)  NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'hidden')),
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 動作確認用のサンプル店舗
INSERT INTO shops (name, category, address, phone, open_time, close_time, closed_days, description) VALUES
('まちかど珈琲', 'カフェ', '駅前通り1-2-3', '000-000-0001', '08:00', '18:00', '水曜日', '地元の焙煎所の豆を使ったコーヒー店です。'),
('さくら食堂',   '飲食店', '本町2-4-6',     '000-000-0002', '11:00', '21:00', '月曜日', '地元野菜を使った定食が人気です。'),
('ひまわり商店', '雑貨',   '中央1-1-1',     '000-000-0003', '10:00', '19:00', 'なし',   '地域の特産品やお土産を扱っています。');

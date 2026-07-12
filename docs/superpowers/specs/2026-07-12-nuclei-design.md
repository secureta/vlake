# nuclei-templates データセット追加 — 設計書

Date: 2026-07-12
Status: Approved

## 目的

vulnlake に **nuclei-templates**(提供: ProjectDiscovery)のテンプレート索引を追加する。
リポジトリ内の全テンプレート YAML の `info` ブロックをメタデータとして Parquet 化して
収録し、テンプレート本文は URL で参照する(本文は再配布しない)。
`classification.cve-id` を結合キーとして、既存の CVE / EPSS / GHSA / ExploitDB と
同じレイク上で「この CVE を検出できる nuclei テンプレートはあるか」を問い合わせ可能にする。

```sql
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;
SELECT template_id, name, severity, template_url
FROM vlake.nuclei
WHERE list_contains(cve, 'CVE-2024-3400') AND NOT removed;
```

## 前提調査の結論

- 上流リポジトリ `https://github.com/projectdiscovery/nuclei-templates` は **MIT License**。
  複製・改変・再配布を許諾。義務は著作権表示とライセンス文の添付のみ。
  安全側に倒し `licenses/MIT-nuclei-templates.txt`(ProjectDiscovery の著作権表示 +
  MIT 全文)を同梱する。
- 収録するのはテンプレートの `info` ブロック由来のメタデータのみ。YAML 本文
  (マッチャー・ペイロード)は再配布せず `template_url` で参照する。
- テンプレート数は約 1.2 万。**YAML に更新日時フィールドが無い**ため、既存データセットの
  「更新日時ウォーターマーク」方式が使えない。本設計の中心はその代替である
  **内容ハッシュによる差分検出**。

## 上流データ

- 取得元: `https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/main`
  (リポジトリ tarball。ghsa と同じ方式で httpx ストリーミング DL)。
- 対象: tarball 内の `.yaml` / `.yml` のうち、トップレベルに `id` と `info` を持つもの。
  `.github/`・`helpers/`・`profiles/` 配下は名前で読み飛ばす(展開しない)。
  workflows / dast / code などのディレクトリも `id` + `info` を満たせば収録する。
- `info` ブロックの実フォーマット(CVE-2024-3400 で確認):
  - `name`, `severity`, `description`, `reference`(リスト), `tags`(カンマ区切り文字列)
  - `author`: カンマ区切り文字列またはリスト
  - `classification`: `cve-id`(文字列またはリスト)、`cwe-id`(カンマ区切りまたはリスト)、
    `cvss-metrics`, `cvss-score`, `epss-score`, `epss-percentile`, `cpe`
  - `metadata`: `verified`, `vendor`, `product`, ほか自由形式(shodan-query 等は収録しない)
- ファイル末尾に ProjectDiscovery の署名行 `# digest: <hex>` が付く(再署名で内容が
  変わらなくても更新されうる)。

## アーキテクチャ

既存のデータセットプラグイン構造に倣うが、**update のみで完結**する(backfill 無し)。
初回の `vlake update nuclei` はカタログが空なので全テンプレートが「新規」となり、
1 ファイル(数 MB)に収まる。年パーティションの根拠となる日付が上流に存在しないため、
これが自然な初期投入となる。EPSS が履歴型の例外であるのと同様、nuclei は
「backfill を持たない」例外としてドキュメント化する。

### 差分検出(本設計の中心)

- 各テンプレートについて、**署名行(`# digest:` で始まる行)を除いた**ファイルバイト列の
  SHA-256 を `digest` 列に保存する。署名行を除くのは、内容が変わらない再署名で
  差分が発生する空振りを防ぐため。
- update 時はカタログ latest ビューの `template_id → (digest, file, removed)` と
  取得断面を比較し、次の行だけを追記する:
  1. **新規**: latest に無い template_id。
  2. **変更**: digest または file(パス移動)が異なる。
  3. **復活**: latest で `removed = true` だったものが断面に再出現(`removed = false` で追記)。
  4. **削除**: latest で `removed = false` だが断面に無い template_id。最新行の値を
     引き継ぎ `removed = true`・`fetched_date = 実行日` のトゥームストーン行を追記する
     (消費者からは「最後に知られた姿 + removed フラグ」として見える)。
- **異常断面ガード**: 取得断面のテンプレート数が latest の有効数(`removed = false`)の
  半分未満なら、上流やダウンロードの異常とみなし例外で中断する(大量トゥームストーンの
  誤生成を防ぐ)。カタログ未更新のまま終わるので消費者影響は無い。
- 同一 template_id が複数ファイルに現れた場合はパスの辞書順で最初の 1 件を採用し、
  残りは重複としてカウントする(上流は id 一意を強制しており実際上は起きない)。

### スキーマ

```sql
-- append-only 履歴テーブル
CREATE TABLE nuclei_history (
  template_id     VARCHAR,      -- CVE-2024-3400, git-config など(リポジトリ内一意)
  name            VARCHAR,
  severity        VARCHAR,      -- info, low, medium, high, critical, unknown
  description     VARCHAR,
  author          VARCHAR[],    -- カンマ区切り文字列/リストの両形式を配列に正規化
  tags            VARCHAR[],    -- カンマ区切りを配列化(cve, kev, rce, ...)
  reference       VARCHAR[],
  cve             VARCHAR[],    -- classification.cve-id(文字列/リスト両対応、大文字化)
  cwe             VARCHAR[],    -- classification.cwe-id(カンマ区切り/リスト両対応)
  cvss_score      DOUBLE,
  cvss_metrics    VARCHAR,
  epss_score      DOUBLE,       -- テンプレート作成・更新時点の埋め込みスナップショット。
  epss_percentile DOUBLE,       -- 最新値はレイクの epss テーブルが真実源
  cpe             VARCHAR,
  vendor          VARCHAR,      -- metadata.vendor
  product         VARCHAR,      -- metadata.product
  verified        BOOLEAN,      -- metadata.verified(無ければ false)
  type            VARCHAR,      -- http, network, dns, file, headless, ssl, websocket,
                                -- whois, code, javascript, workflows(トップレベルキーから判定)
  file            VARCHAR,      -- リポジトリ相対パス http/cves/2024/CVE-2024-3400.yaml
  template_url    VARCHAR,      -- https://github.com/projectdiscovery/nuclei-templates/blob/main/{file}
  digest          VARCHAR,      -- 署名行を除いた内容の SHA-256(hex)
  fetched_date    DATE,         -- 取り込み実行日。latest ビューの順序付けキー
  removed         BOOLEAN       -- トゥームストーン(上流から消えた)
);

-- template_id ごと fetched_date 最新の1行を返すビュー(CREATE OR REPLACE で毎回作り直す)
CREATE VIEW nuclei AS SELECT ... latest per template_id by fetched_date ...;
```

- `type`: トップレベルキーのうち既知プロトコル
  (`http`, `requests`(旧形式、`http` に正規化), `network`, `tcp`(`network` に正規化),
  `dns`, `file`, `headless`, `ssl`, `websocket`, `whois`, `code`, `javascript`,
  `workflows`)に最初に一致したもの。どれも無ければ NULL。
- `cve`: 大文字化して `CVE-\d{4}-\d+` 形式のみ採用。該当なしは空配列 `[]`。
- `severity` 等の欠損は NULL。`verified` のみ欠損を false とする。
- パース不能な YAML(safe_load 失敗)・`id`/`info` 欠落は bad としてカウントし読み飛ばす。

### データレイアウト

```
s3://<bucket>/
  nuclei/
    updates/
      year=2026/nuclei-updates-2026-07-12.parquet   # 日次差分(実行日でラベル、初回は全量)
```

backfill 用の `year=YYYY/` スナップショットは存在しない。

### ライセンス情報(`nuclei.LICENSE_INFO`)

```python
LICENSE_INFO = {
    "name": "nuclei",
    "source_url": "https://github.com/projectdiscovery/nuclei-templates",
    "license_name": "MIT",
    "license_text": (
        "MIT License (https://opensource.org/license/mit). "
        "This dataset is a modified form of the nuclei-templates repository: "
        "template info-block metadata extracted from YAML and converted to "
        "Parquet. Template bodies (matchers/payloads) are not redistributed; "
        "each row links to the template via template_url."
    ),
    "attribution": (
        "nuclei-templates — © ProjectDiscovery, Inc. "
        "(https://github.com/projectdiscovery/nuclei-templates), "
        "licensed under the MIT License."
    ),
    "disclaimer": (
        "This project redistributes nuclei-templates metadata but is not "
        "endorsed or certified by ProjectDiscovery, Inc."
    ),
}
```

## CLI

- `vlake update nuclei` — tarball を取得し差分行だけを追記(初回は全量)。
  `--date` 非対応(常に最新断面)。
- `vlake backfill nuclei` は**提供しない**(Choice に追加しない)。
- 既存の `vlake verify` / `vlake rebuild-catalog` は nuclei も対象に含める。

## 取り込み・更新フロー(`update_nuclei`)

1. 差分キー `nuclei/updates/year=YYYY/nuclei-updates-<run_date>.parquet` が登録済みなら
   `already-registered` で終了。
2. tarball をダウンロードし、対象 YAML を逐次パースして
   `template_id → (digest, 行)` の断面を構築。
3. カタログ latest の `template_id → (digest, file, removed)` を取得
   (カタログが空 = 初回なら全件が新規。**refused ガードは置かない**)。
4. 異常断面ガード: 初回以外で断面数 < latest 有効数の半分なら例外で中断。
5. 追記対象 = 新規 + 変更(digest / file 差)+ 復活 + トゥームストーン。
   空なら `no-new-records`。
6. 差分 Parquet(template_id ソート、zstd)を生成・アップロード・
   `nuclei_history` に登録・カタログ公開
   (Parquet が先、カタログ差し替えが後の不変条件を維持)。

## lake.py の変更

- `ensure_tables()`: `nuclei_history` を追加。
- `refresh_nuclei_view()`: template_id ごと `fetched_date` 最新(同値タイは最後に追記された行)
  を返す `nuclei` ビューを `CREATE OR REPLACE`。
- `nuclei_latest_state()`: 差分検出用に latest 相当の
  `template_id → (digest, file, removed)` を返す(空なら空 dict)。
  `max_*` ウォーターマーク方式は使わない。

## pipeline.py の変更

- `update_nuclei` を追加(backfill_* は追加しない)。
- `_publish_catalog` の datasets 一覧に `nuclei.LICENSE_INFO` を追加、
  `refresh_nuclei_view()` を呼ぶ。
- `rebuild_catalog` の table マップに `"nuclei/": "nuclei_history"` を追加。
- `verify`: nuclei を履歴系の検証に含める(`fetched_date` は DATE。exploitdb 対応で
  DATE / TIMESTAMP 両対応済みの `_verify_history` をそのまま使う)。

## 依存追加

- YAML パースに `pyyaml` を追加(`yaml.safe_load`、利用可能なら CSafeLoader)。
  バージョンはレジストリで最新安定版を確認して指定する。

## 運用(GitHub Actions)

- `publish.yml` の日次ジョブに `vlake update nuclei` を追加。
- `backfill.yml` には**追加しない**(backfill が存在しないため)。

## ライセンス文書・README

- `licenses/MIT-nuclei-templates.txt` — ProjectDiscovery の著作権表示 + MIT 全文。
- `DATA_LICENSES.md` — nuclei の節を追加(source / license / 改変の明示 /
  attribution / disclaimer / 本文非同梱の設計)。
- `README.md` — スキーマ・クエリ例・データライセンス節を更新。
  backfill が無い旨(初回 update が全量投入)も明記。

## エラー処理

- tarball 取得失敗(ネットワーク): 例外送出、次回 cron で再試行
  (カタログ未更新なら消費者影響なし)。
- 壊れた YAML / `id`・`info` 欠落: スキップしてカウント(bad)。処理は継続。
- 断面の異常縮小: 前述のガードで中断(大量トゥームストーン防止)。
- 差分キー重複登録: 登録前照会で防止(`already-registered`)。
- カタログ破損: `vlake rebuild-catalog` で再構築。
- アップロード途中失敗: Parquet が先・カタログが後の順序なので、次回実行が冪等に回復。

## テスト

- conftest に `make_nuclei_tarball` を追加: 実テンプレート形式(`id` / `info` /
  `classification` / `metadata` / 末尾 `# digest:` 署名行)を忠実に模した YAML 群から
  tar.gz を生成する。`.github/` 配下や `helpers/` のダミー、id/info 欠落 YAML も混ぜる。
- 単体(`test_nuclei.py`):
  - info パース: author の文字列/リスト両対応、cve-id の文字列/リスト、cwe-id の
    カンマ区切り、classification 欠落、tags 配列化、type 判定(http / requests 正規化 /
    workflows / 不明)。
  - digest: 署名行の有無・署名行だけの変更で digest が変わらないこと。
  - `template_url` 構築、除外パスの読み飛ばし。
- 統合(`test_pipeline_nuclei.py`):
  - 初回 update = 全量投入 → 2 回目は `no-new-records`(冪等)。
  - 変更・追加・削除を含む 2 断面目 → 差分行のみ追記、トゥームストーンの生成、
    latest ビューで `removed` の見え方、復活時の `removed = false`。
  - 異常縮小断面での中断(カタログ非更新)。
  - `already-registered`、verify が通ること、DuckDB で ATTACH して
    `list_contains(cve, ...)` が引けること。

## スコープ外(将来課題)

- テンプレート YAML 本文の収録(現状は URL 参照のみ)。
- `metadata` の自由形式フィールド(shodan-query, fofa-query 等)の収録。
- 過去差分ファイルのコンパクション(他データセットと共通の将来課題)。

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LLMS_DOC = ROOT / "docs" / "llms.md"
README = ROOT / "README.md"
SCHEMA_DOC = ROOT / "docs" / "schema.md"
PUBLISH_DOCS_WORKFLOW = ROOT / ".github" / "workflows" / "publish-docs.yml"


def test_llms_doc_is_a_compact_query_guide() -> None:
    text = LLMS_DOC.read_text()

    assert "https://vlake.reta.work/vlake.ducklake" in text
    assert "Use latest views for current state" in text
    assert "Use history tables only" in text
    assert "`vlake.epss` is daily history" in text
    assert "AND NOT removed" in text
    assert "list_contains" in text
    assert "UNNEST(affected)" in text
    assert "DESCRIBE vlake.<table>" in text
    assert "SELECT * FROM vlake.datasets" in text

    # LLM の入口文書は完全なスキーマ参照ではなく、判断ルールと代表クエリを優先する。
    assert "## Full schema" not in text
    assert len(text.splitlines()) < 220


def test_readme_links_to_public_llms_txt() -> None:
    text = README.read_text()

    assert "## For LLMs" in text
    assert "https://vlake.reta.work/llms.txt" in text


def test_schema_reference_lives_in_docs_schema() -> None:
    readme = README.read_text()
    schema = SCHEMA_DOC.read_text()

    assert "[full schema reference](docs/schema.md)" in readme
    assert "| Column | Type | Description |" not in readme
    assert "# vulnlake schema reference" in schema
    assert "| Column | Type | Description |" in schema
    assert "### `epss`" in schema
    assert "### `datasets`" in schema


def test_llms_doc_links_to_schema_reference_file() -> None:
    text = LLMS_DOC.read_text()

    assert "https://github.com/secureta/vlake/blob/main/docs/schema.md" in text
    assert "https://github.com/secureta/vlake#schema" not in text


def test_schema_doc_relative_links_resolve() -> None:
    # docs/schema.md は docs/ 配下にあるため、ルートの DATA_LICENSES.md への
    # 相対リンクは ../ を付けないと解決しない (README から移設した際の破損防止)。
    import re

    schema = SCHEMA_DOC.read_text()
    for match in re.finditer(r"\]\((?!https?://|#)([^)]+)\)", schema):
        target = match.group(1).split("#", 1)[0]
        if not target:
            continue
        resolved = (SCHEMA_DOC.parent / target).resolve()
        assert resolved.exists(), f"broken relative link in docs/schema.md: {target}"


def test_docs_workflow_publishes_llms_txt_with_markdown_headers() -> None:
    text = PUBLISH_DOCS_WORKFLOW.read_text()

    assert "docs/llms.md" in text
    assert 's3 cp docs/llms.md "s3://$VLAKE_S3_BUCKET/llms.txt"' in text
    assert "--content-type 'text/markdown; charset=utf-8'" in text
    assert "--cache-control 'public, max-age=3600'" in text
    assert '--endpoint-url "$VLAKE_S3_ENDPOINT"' in text
    assert "environment: publish" in text
    assert "persist-credentials: false" in text

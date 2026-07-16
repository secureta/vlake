import json
from datetime import date

import duckdb
import pytest

from vlake import mitre, pipeline
from vlake.config import Config


@pytest.fixture
def cfg(tmp_path):
    return Config(
        s3_endpoint=None,
        s3_bucket=None,
        public_url=None,
        local_dir=tmp_path / "bucket",
    )


def _attach(cfg):
    con = duckdb.connect()
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(
        f"ATTACH 'ducklake:{cfg.local_dir / 'vlake.ducklake'}' AS frozen (READ_ONLY)"
    )
    return con


def _bundle(objects):
    return json.dumps(
        {"type": "bundle", "id": "bundle--sample", "objects": objects}
    ).encode()


ENTERPRISE_BUNDLE = _bundle(
    [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1190",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may exploit public-facing applications.",
            "modified": "2026-01-02T03:04:05.000Z",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1190",
                    "url": "https://attack.mitre.org/techniques/T1190/",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--ta0001",
            "name": "Initial Access",
            "modified": "2026-01-01T00:00:00.000Z",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0001"}
            ],
        },
    ]
)

MOBILE_BUNDLE = _bundle(
    [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1634",
            "name": "Credentials in Registry",
            "modified": "2026-01-04T00:00:00.000Z",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1634"}
            ],
        }
    ]
)

ICS_BUNDLE = _bundle(
    [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t0814",
            "name": "Denial of Service",
            "modified": "2026-01-05T00:00:00.000Z",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T0814"}
            ],
        }
    ]
)

CAPEC_BUNDLE = _bundle(
    [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--capec-66",
            "name": "SQL Injection",
            "description": "An attacker injects SQL.",
            "modified": "2026-02-03T04:05:06.000Z",
            "external_references": [
                {"source_name": "capec", "external_id": "CAPEC-66"},
                {"source_name": "cwe", "external_id": "CWE-89"},
                {"source_name": "mitre-attack", "external_id": "T1190"},
            ],
        }
    ]
)


def test_update_attack_and_capec_publish_views_relationships_and_join(cfg, monkeypatch):
    monkeypatch.setattr(mitre, "fetch_attack_enterprise", lambda: ENTERPRISE_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_attack_mobile", lambda: MOBILE_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_attack_ics", lambda: ICS_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_capec", lambda: CAPEC_BUNDLE)

    assert (
        pipeline.update_attack(cfg, today=date(2026, 7, 10))
        == "published 2026-07-10 (4 objects, 0 relationships)"
    )
    assert (
        pipeline.update_capec(cfg, today=date(2026, 7, 10))
        == "published 2026-07-10 (1 records)"
    )

    con = _attach(cfg)
    assert con.execute("SELECT count(*) FROM frozen.attack_history").fetchone()[0] == 4
    assert (
        con.execute(
            "SELECT count(*) FROM frozen.attack_relationship_history"
        ).fetchone()[0]
        == 0
    )
    assert con.execute("SELECT count(*) FROM frozen.capec_history").fetchone()[0] == 1
    assert (
        con.execute(
            "SELECT name FROM frozen.attack WHERE matrix = 'enterprise' AND attack_id = 'T1190'"
        ).fetchone()[0]
        == "Exploit Public-Facing Application"
    )
    assert con.execute(
        "SELECT matrix, attack_id FROM frozen.attack ORDER BY matrix, attack_id"
    ).fetchall() == [
        ("enterprise", "T1190"),
        ("enterprise", "TA0001"),
        ("ics", "T0814"),
        ("mobile", "T1634"),
    ]
    assert (
        con.execute(
            "SELECT name FROM frozen.capec WHERE capec_id = 'CAPEC-66'"
        ).fetchone()[0]
        == "SQL Injection"
    )

    joined = con.execute(
        """
        SELECT cwe, capec_id, attack_id, attack_name
        FROM frozen.cwe_attack_patterns
        ORDER BY cwe, capec_id, attack_id
        """
    ).fetchall()
    assert joined == [
        ("CWE-89", "CAPEC-66", "T1190", "Exploit Public-Facing Application")
    ]
    names = {r[0] for r in con.execute("SELECT name FROM frozen.datasets").fetchall()}
    assert {"attack", "capec"}.issubset(names)


def test_update_attack_is_idempotent_by_run_date(cfg, monkeypatch):
    monkeypatch.setattr(mitre, "fetch_attack_enterprise", lambda: ENTERPRISE_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_attack_mobile", lambda: MOBILE_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_attack_ics", lambda: ICS_BUNDLE)
    assert pipeline.update_attack(cfg, today=date(2026, 7, 10)).startswith("published")
    assert (
        pipeline.update_attack(cfg, today=date(2026, 7, 10))
        == "already-registered 2026-07-10"
    )


def test_update_attack_publishes_relationships(cfg, monkeypatch):
    bundle = _bundle(
        [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt-sample",
                "name": "Sample APT",
                "modified": "2026-01-01T00:00:00.000Z",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0001"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1190",
                "name": "Exploit Public-Facing Application",
                "modified": "2026-01-02T00:00:00.000Z",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--uses-sample",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt-sample",
                "target_ref": "attack-pattern--t1190",
                "modified": "2026-01-03T00:00:00.000Z",
            },
        ]
    )
    monkeypatch.setattr(mitre, "fetch_attack_enterprise", lambda: bundle)
    monkeypatch.setattr(mitre, "fetch_attack_mobile", lambda: _bundle([]))
    monkeypatch.setattr(mitre, "fetch_attack_ics", lambda: _bundle([]))

    assert (
        pipeline.update_attack(cfg, today=date(2026, 7, 10))
        == "published 2026-07-10 (2 objects, 1 relationships)"
    )
    con = _attach(cfg)
    assert con.execute(
        """
        SELECT matrix, relationship_type, source_attack_id, source_name,
               target_attack_id, target_name
        FROM frozen.attack_relationship
        """
    ).fetchall() == [
        (
            "enterprise",
            "uses",
            "G0001",
            "Sample APT",
            "T1190",
            "Exploit Public-Facing Application",
        )
    ]


def test_verify_and_rebuild_cover_attack_and_capec(cfg, monkeypatch):
    monkeypatch.setattr(mitre, "fetch_attack_enterprise", lambda: ENTERPRISE_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_attack_mobile", lambda: MOBILE_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_attack_ics", lambda: ICS_BUNDLE)
    monkeypatch.setattr(mitre, "fetch_capec", lambda: CAPEC_BUNDLE)
    pipeline.update_attack(cfg, today=date(2026, 7, 10))
    pipeline.update_capec(cfg, today=date(2026, 7, 10))

    report = pipeline.verify(cfg)
    assert report["ok"] is True
    assert report["datasets"]["attack"]["row_count"] == 4
    assert report["datasets"]["attack_relationship"]["row_count"] == 0
    assert report["datasets"]["capec"]["row_count"] == 1

    (cfg.local_dir / "vlake.ducklake").unlink()
    assert pipeline.rebuild_catalog(cfg) == "rebuilt catalog with 2 files"
    con = _attach(cfg)
    assert (
        con.execute("SELECT count(*) FROM frozen.cwe_attack_patterns").fetchone()[0]
        == 1
    )

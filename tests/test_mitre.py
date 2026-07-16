import json
from datetime import datetime

from vlake import mitre


def _bundle(objects):
    return json.dumps(
        {"type": "bundle", "id": "bundle--sample", "objects": objects}
    ).encode()


def test_parse_attack_bundle_extracts_enterprise_objects_with_matrix():
    raw = _bundle(
        [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1190",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may exploit public-facing applications.",
                "modified": "2026-01-02T03:04:05.000Z",
                "revoked": False,
                "x_mitre_deprecated": False,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1190",
                        "url": "https://attack.mitre.org/techniques/T1190/",
                    }
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--ta0001",
                "name": "Initial Access",
                "modified": "2026-01-01T00:00:00.000Z",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "TA0001",
                        "url": "https://attack.mitre.org/tactics/TA0001/",
                    }
                ],
            },
            {"type": "relationship", "id": "relationship--ignored"},
        ]
    )

    rows = mitre.parse_attack_bundle(raw, matrix="enterprise")

    assert [(r["matrix"], r["attack_id"]) for r in rows] == [
        ("enterprise", "T1190"),
        ("enterprise", "TA0001"),
    ]
    technique = rows[0]
    assert technique["object_id"] == "attack-pattern--t1190"
    assert technique["object_type"] == "attack-pattern"
    assert technique["name"] == "Exploit Public-Facing Application"
    assert technique["kill_chain_phases"] == [
        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
    ]
    assert technique["modified"] == datetime(2026, 1, 2, 3, 4, 5)
    assert json.loads(technique["raw"])["id"] == "attack-pattern--t1190"


def test_parse_attack_relationships_resolves_source_and_target_objects():
    raw = _bundle(
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
                "modified": "2026-01-02T03:04:05.000Z",
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
                "description": "Sample APT uses public-facing application exploits.",
                "modified": "2026-01-03T00:00:00.000Z",
            },
        ]
    )

    rows = mitre.parse_attack_relationships(raw, matrix="enterprise")

    assert rows == [
        {
            "matrix": "enterprise",
            "relationship_id": "relationship--uses-sample",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--apt-sample",
            "source_attack_id": "G0001",
            "source_name": "Sample APT",
            "source_type": "intrusion-set",
            "target_ref": "attack-pattern--t1190",
            "target_attack_id": "T1190",
            "target_name": "Exploit Public-Facing Application",
            "target_type": "attack-pattern",
            "description": "Sample APT uses public-facing application exploits.",
            "revoked": False,
            "deprecated": False,
            "modified": datetime(2026, 1, 3, 0, 0, 0),
            "raw": json.dumps(
                {
                    "description": "Sample APT uses public-facing application exploits.",
                    "id": "relationship--uses-sample",
                    "modified": "2026-01-03T00:00:00.000Z",
                    "relationship_type": "uses",
                    "source_ref": "intrusion-set--apt-sample",
                    "target_ref": "attack-pattern--t1190",
                    "type": "relationship",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        }
    ]


def test_parse_capec_bundle_extracts_cwe_and_attack_mapping():
    raw = _bundle(
        [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--capec-66",
                "name": "SQL Injection",
                "description": "An attacker injects SQL.",
                "modified": "2026-02-03T04:05:06.000Z",
                "external_references": [
                    {
                        "source_name": "capec",
                        "external_id": "CAPEC-66",
                        "url": "https://capec.mitre.org/data/definitions/66.html",
                    },
                    {"source_name": "cwe", "external_id": "CWE-89"},
                    {"source_name": "cwe", "external_id": "CWE-89"},
                    {"source_name": "ATTACK", "external_id": "T1190"},
                    {"source_name": "mitre-attack", "external_id": "T1059"},
                ],
            },
            {"type": "identity", "id": "identity--ignored"},
        ]
    )

    rows = mitre.parse_capec_bundle(raw)

    assert len(rows) == 1
    row = rows[0]
    assert row["capec_id"] == "CAPEC-66"
    assert row["cwe"] == ["CWE-89"]
    assert row["attack"] == ["T1190", "T1059"]
    assert row["modified"] == datetime(2026, 2, 3, 4, 5, 6)


def test_rows_to_table_match_schemas():
    attack_bundle = _bundle(
        [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1190",
                "name": "Exploit Public-Facing Application",
                "modified": "2026-01-02T03:04:05.000Z",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--sample",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--missing",
                "target_ref": "attack-pattern--t1190",
                "modified": "2026-01-03T00:00:00.000Z",
            },
        ]
    )
    attack_rows = mitre.parse_attack_bundle(attack_bundle, matrix="enterprise")
    relationship_rows = mitre.parse_attack_relationships(
        attack_bundle, matrix="enterprise"
    )
    capec_rows = mitre.parse_capec_bundle(
        _bundle(
            [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--capec-66",
                    "name": "SQL Injection",
                    "modified": "2026-02-03T04:05:06.000Z",
                    "external_references": [
                        {"source_name": "capec", "external_id": "CAPEC-66"}
                    ],
                }
            ]
        )
    )

    assert mitre.attack_rows_to_table(attack_rows).schema.equals(mitre.ATTACK_SCHEMA)
    assert mitre.attack_relationship_rows_to_table(relationship_rows).schema.equals(
        mitre.ATTACK_RELATIONSHIP_SCHEMA
    )
    assert mitre.capec_rows_to_table(capec_rows).schema.equals(mitre.CAPEC_SCHEMA)


def test_key_for_update():
    assert (
        mitre.attack_key_for_update("2026-07-10")
        == "attack/updates/year=2026/attack-2026-07-10.parquet"
    )
    assert (
        mitre.attack_relationship_key_for_update("2026-07-10")
        == "attack/relationships/year=2026/attack-relationships-2026-07-10.parquet"
    )
    assert (
        mitre.capec_key_for_update("2026-07-10")
        == "capec/updates/year=2026/capec-2026-07-10.parquet"
    )

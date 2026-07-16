"""MITRE ATT&CK Enterprise / CAPEC データセット。

データ提供: The MITRE Corporation。ATT&CK と CAPEC の STIX 2.1 bundle から
公開クエリで使いやすい主要フィールドを抽出して Parquet に変換する (変更あり)。
本プロジェクトは MITRE の公認・認証を受けたものではない。
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

ATTACK_NAME = "attack"
CAPEC_NAME = "capec"

ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
ATTACK_MOBILE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/mobile-attack/mobile-attack.json"
)
ATTACK_ICS_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/ics-attack/ics-attack.json"
)
CAPEC_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
)

_KILL_CHAIN_TYPE = pa.list_(
    pa.struct([("kill_chain_name", pa.string()), ("phase_name", pa.string())])
)

ATTACK_SCHEMA = pa.schema(
    [
        ("matrix", pa.string()),
        ("attack_id", pa.string()),
        ("object_id", pa.string()),
        ("object_type", pa.string()),
        ("name", pa.string()),
        ("description", pa.string()),
        ("url", pa.string()),
        ("kill_chain_phases", _KILL_CHAIN_TYPE),
        ("revoked", pa.bool_()),
        ("deprecated", pa.bool_()),
        ("modified", pa.timestamp("us")),
        ("raw", pa.string()),
    ]
)

ATTACK_RELATIONSHIP_SCHEMA = pa.schema(
    [
        ("matrix", pa.string()),
        ("relationship_id", pa.string()),
        ("relationship_type", pa.string()),
        ("source_ref", pa.string()),
        ("source_attack_id", pa.string()),
        ("source_name", pa.string()),
        ("source_type", pa.string()),
        ("target_ref", pa.string()),
        ("target_attack_id", pa.string()),
        ("target_name", pa.string()),
        ("target_type", pa.string()),
        ("description", pa.string()),
        ("revoked", pa.bool_()),
        ("deprecated", pa.bool_()),
        ("modified", pa.timestamp("us")),
        ("raw", pa.string()),
    ]
)

CAPEC_SCHEMA = pa.schema(
    [
        ("capec_id", pa.string()),
        ("object_id", pa.string()),
        ("name", pa.string()),
        ("description", pa.string()),
        ("url", pa.string()),
        ("cwe", pa.list_(pa.string())),
        ("attack", pa.list_(pa.string())),
        ("revoked", pa.bool_()),
        ("deprecated", pa.bool_()),
        ("modified", pa.timestamp("us")),
        ("raw", pa.string()),
    ]
)

ATTACK_LICENSE_INFO = {
    "name": ATTACK_NAME,
    "source_url": "https://github.com/mitre-attack/attack-stix-data",
    "license_name": "MITRE ATT&CK Terms of Use",
    "license_text": (
        "MITRE grants a non-exclusive, royalty-free license to use ATT&CK for "
        "research, development, and commercial purposes, provided copies reproduce "
        "MITRE's copyright designation and license. This dataset is a modified "
        "form of the Enterprise, Mobile, and ICS ATT&CK STIX bundles converted "
        "to Parquet."
    ),
    "attribution": (
        "ATT&CK® — © 2026 The MITRE Corporation. This work is reproduced and "
        "distributed with the permission of The MITRE Corporation."
    ),
    "disclaimer": (
        "This project redistributes ATT&CK content but is not endorsed or "
        "certified by The MITRE Corporation."
    ),
}

CAPEC_LICENSE_INFO = {
    "name": CAPEC_NAME,
    "source_url": "https://github.com/mitre/cti/tree/master/capec/2.1",
    "license_name": "MITRE CAPEC Terms of Use",
    "license_text": (
        "MITRE grants a non-exclusive, royalty-free license to use CAPEC for "
        "research, development, and commercial purposes, provided copies reproduce "
        "MITRE's copyright designation and license. This dataset is a modified "
        "form of the CAPEC STIX bundle converted to Parquet."
    ),
    "attribution": "CAPEC™ — © The MITRE Corporation (https://capec.mitre.org/).",
    "disclaimer": (
        "This project redistributes CAPEC content but is not endorsed or "
        "certified by The MITRE Corporation."
    ),
}


def _ts(value: str | None) -> datetime | None:
    """STIX の ISO 8601 timestamp を UTC ナイーブ datetime にする。"""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _external_refs(obj: dict[str, Any]) -> list[dict[str, Any]]:
    refs = obj.get("external_references") or []
    return [r for r in refs if isinstance(r, dict)]


def _external_id(obj: dict[str, Any], source: str) -> str | None:
    for ref in _external_refs(obj):
        if ref.get("source_name") == source and ref.get("external_id"):
            return ref["external_id"]
    return None


def _url_for(obj: dict[str, Any], source: str) -> str | None:
    for ref in _external_refs(obj):
        if ref.get("source_name") == source and ref.get("url"):
            return ref["url"]
    return None


def _external_ids(
    obj: dict[str, Any], sources: tuple[str, ...], prefix: str
) -> list[str]:
    ids: list[str] = []
    for ref in _external_refs(obj):
        ext = ref.get("external_id")
        if (
            ref.get("source_name") in sources
            and isinstance(ext, str)
            and ext.startswith(prefix)
        ):
            if ext not in ids:
                ids.append(ext)
    return ids


def _kill_chain_phases(obj: dict[str, Any]) -> list[dict[str, str]]:
    phases = []
    for phase in obj.get("kill_chain_phases") or []:
        if not isinstance(phase, dict):
            continue
        name = phase.get("kill_chain_name")
        phase_name = phase.get("phase_name")
        if name and phase_name:
            phases.append({"kill_chain_name": name, "phase_name": phase_name})
    return phases


def _attack_object_index(bundle: dict) -> dict[str, dict]:
    """relationship 解決用に STIX object id から主要情報へ引ける索引を作る。"""
    index = {}
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, dict) or obj.get("type") == "relationship":
            continue
        index[obj.get("id")] = {
            "attack_id": _external_id(obj, "mitre-attack"),
            "name": obj.get("name"),
            "type": obj.get("type"),
        }
    return index


def parse_attack_bundle(raw: bytes, *, matrix: str = "enterprise") -> list[dict]:
    """ATT&CK STIX bundle から主要 SDO 行を抽出する。"""
    bundle = json.loads(raw)
    rows = []
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        typ = obj.get("type")
        if typ not in {
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "malware",
            "tool",
            "x-mitre-data-source",
            "x-mitre-data-component",
            "x-mitre-tactic",
        }:
            continue
        attack_id = _external_id(obj, "mitre-attack")
        if not attack_id:
            continue
        rows.append(
            {
                "matrix": matrix,
                "attack_id": attack_id,
                "object_id": obj.get("id"),
                "object_type": typ,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "url": _url_for(obj, "mitre-attack"),
                "kill_chain_phases": _kill_chain_phases(obj),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "modified": _ts(obj.get("modified")),
                "raw": json.dumps(obj, ensure_ascii=False, sort_keys=True),
            }
        )
    rows.sort(
        key=lambda r: (r["matrix"], r["attack_id"], r["modified"] or datetime.min)
    )
    return rows


def parse_attack_relationships(raw: bytes, *, matrix: str = "enterprise") -> list[dict]:
    """ATT&CK STIX bundle から relationship SRO 行を抽出する。"""
    bundle = json.loads(raw)
    index = _attack_object_index(bundle)
    rows = []
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        source = index.get(source_ref, {})
        target = index.get(target_ref, {})
        rows.append(
            {
                "matrix": matrix,
                "relationship_id": obj.get("id"),
                "relationship_type": obj.get("relationship_type"),
                "source_ref": source_ref,
                "source_attack_id": source.get("attack_id"),
                "source_name": source.get("name"),
                "source_type": source.get("type"),
                "target_ref": target_ref,
                "target_attack_id": target.get("attack_id"),
                "target_name": target.get("name"),
                "target_type": target.get("type"),
                "description": obj.get("description"),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "modified": _ts(obj.get("modified")),
                "raw": json.dumps(obj, ensure_ascii=False, sort_keys=True),
            }
        )
    rows.sort(
        key=lambda r: (
            r["matrix"],
            r["relationship_id"] or "",
            r["modified"] or datetime.min,
        )
    )
    return rows


def parse_capec_bundle(raw: bytes) -> list[dict]:
    """CAPEC STIX bundle から CAPEC attack-pattern 行を抽出する。"""
    bundle = json.loads(raw)
    rows = []
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        capec_id = _external_id(obj, "capec")
        if not capec_id:
            continue
        rows.append(
            {
                "capec_id": capec_id,
                "object_id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "url": _url_for(obj, "capec"),
                "cwe": _external_ids(obj, ("cwe",), "CWE-"),
                "attack": _external_ids(obj, ("mitre-attack", "ATTACK"), "T"),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "modified": _ts(obj.get("modified")),
                "raw": json.dumps(obj, ensure_ascii=False, sort_keys=True),
            }
        )
    rows.sort(key=lambda r: (r["capec_id"], r["modified"] or datetime.min))
    return rows


def attack_rows_to_table(rows: list[dict]) -> pa.Table:
    """ATT&CK 行リストを PyArrow Table に変換する。"""
    table = pa.Table.from_pylist(rows, schema=ATTACK_SCHEMA)
    return table.sort_by(
        [("matrix", "ascending"), ("attack_id", "ascending"), ("modified", "ascending")]
    )


def attack_relationship_rows_to_table(rows: list[dict]) -> pa.Table:
    """ATT&CK relationship 行リストを PyArrow Table に変換する。"""
    table = pa.Table.from_pylist(rows, schema=ATTACK_RELATIONSHIP_SCHEMA)
    return table.sort_by(
        [
            ("matrix", "ascending"),
            ("relationship_id", "ascending"),
            ("modified", "ascending"),
        ]
    )


def capec_rows_to_table(rows: list[dict]) -> pa.Table:
    """CAPEC 行リストを PyArrow Table に変換する。"""
    table = pa.Table.from_pylist(rows, schema=CAPEC_SCHEMA)
    return table.sort_by([("capec_id", "ascending"), ("modified", "ascending")])


def write_parquet(table: pa.Table, path: Path) -> None:
    """PyArrow Table を Parquet ファイルに書き出す (zstd 圧縮)。"""
    pq.write_table(table, path, compression="zstd")


def fetch_attack_enterprise() -> bytes:
    """Enterprise ATT&CK STIX bundle を取得する。"""
    resp = httpx.get(ATTACK_ENTERPRISE_URL, follow_redirects=True, timeout=600)
    resp.raise_for_status()
    return resp.content


def fetch_attack_mobile() -> bytes:
    """Mobile ATT&CK STIX bundle を取得する。"""
    resp = httpx.get(ATTACK_MOBILE_URL, follow_redirects=True, timeout=600)
    resp.raise_for_status()
    return resp.content


def fetch_attack_ics() -> bytes:
    """ICS ATT&CK STIX bundle を取得する。"""
    resp = httpx.get(ATTACK_ICS_URL, follow_redirects=True, timeout=600)
    resp.raise_for_status()
    return resp.content


def fetch_capec() -> bytes:
    """CAPEC STIX bundle を取得する。"""
    resp = httpx.get(CAPEC_URL, follow_redirects=True, timeout=600)
    resp.raise_for_status()
    return resp.content


def attack_key_for_update(d: date | str) -> str:
    """ATT&CK スナップショットのキー。"""
    if isinstance(d, str):
        d = date.fromisoformat(d)
    return f"attack/updates/year={d.year}/attack-{d.isoformat()}.parquet"


def attack_relationship_key_for_update(d: date | str) -> str:
    """ATT&CK relationship スナップショットのキー。"""
    if isinstance(d, str):
        d = date.fromisoformat(d)
    return f"attack/relationships/year={d.year}/attack-relationships-{d.isoformat()}.parquet"


def capec_key_for_update(d: date | str) -> str:
    """CAPEC スナップショットのキー。"""
    if isinstance(d, str):
        d = date.fromisoformat(d)
    return f"capec/updates/year={d.year}/capec-{d.isoformat()}.parquet"

# PURPOSE: SCP-R4 parallel fetch path — HTTPS + nostr registry snapshot to quarantine (no auto-merge).
# DEPENDENCIES: pattern_record, registry_ssot, antigen_l402, antigen_nostr, scp_utils
# MODIFICATION NOTES: AppSec 2026-08-03 — registry_fetch quarantine layout; streamed body byte cap

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

import requests

from . import antigen
from . import antigen_l402 as l402
from . import antigen_nostr as nostr
from . import http_body
from . import http_policy
from . import pattern_record as pr
from . import quarantine_limits
from . import registry_ssot
from . import scp_utils

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NEVENT_RE = re.compile(r"^nevent1[02-9ac-hj-np-z]+$", re.I)


class RegistryFetchError(Exception):
    def __init__(self, reason: str, *, status: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _parse_allowlist(allowlist: list[str] | None) -> list[str]:
    if not allowlist:
        return []
    return [a.strip() for a in allowlist if a.strip()]


def _host_allowed(url: str, allowlist: list[str]) -> bool:
    return http_policy.host_allowed(url, allowlist)


def _issuer_allowed(pubkey: str, allowlist: list[str]) -> bool:
    if not allowlist:
        return False
    allowed_pubkeys = {a.lower() for a in allowlist if _HEX64.match(a.lower())}
    return pubkey.lower() in allowed_pubkeys


def _resolve_event_id(source: str) -> str:
    if _HEX64.match(source.lower()):
        return source.lower()
    if _NEVENT_RE.match(source):
        raise RegistryFetchError("nevent_decode_not_implemented")
    raise RegistryFetchError("invalid_nostr_source")


def _is_https_source(source: str) -> bool:
    try:
        parsed = urlparse(source)
        return parsed.scheme in ("https", "http")
    except Exception:
        return False


def _write_registry_quarantine(
    snapshot: dict,
    *,
    source: str,
    diff_summary: dict,
) -> dict:
    meta = {
        "reason": "registry_fetch",
        "source": source,
        "etag": snapshot.get("etag"),
        "registry_version": snapshot.get("registry_version"),
        "schema_revision": snapshot.get("schema_revision"),
        "diff_summary": {
            "add_count": diff_summary.get("add_count", 0),
            "conflict_count": diff_summary.get("conflict_count", 0),
            "drift_max": diff_summary.get("drift_max", 0.0),
            "risk_breakdown": diff_summary.get("risk_breakdown", {}),
        },
    }
    envelope = {"snapshot": snapshot, "meta": meta}
    content = json.dumps(envelope, indent=2, ensure_ascii=False)
    q = scp_utils.quarantine(
        content,
        reason="registry_fetch",
        source=source,
        layout=scp_utils.REGISTRY_FETCH_LAYOUT,
    )
    antigen._audit(
        "registry_fetch_quarantine",
        source=source,
        quarantine_id=q["quarantine_id"],
        add_count=diff_summary.get("add_count", 0),
        conflict_count=diff_summary.get("conflict_count", 0),
    )
    return q


def _fetch_https(
    url: str,
    allowlist: list[str],
    *,
    if_none_match: str | None = None,
    tls_verify: bool = True,
    session: requests.Session | None = None,
) -> dict:
    if not _host_allowed(url, allowlist):
        raise RegistryFetchError("host_not_on_allowlist")

    parsed = urlparse(url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
    ):
        raise RegistryFetchError("url_must_be_https")

    if l402.regtest_fetch_hardening_enabled():
        try:
            l402.assert_localhost_fetch_url(url)
        except ValueError:
            raise RegistryFetchError("fetch_url_not_localhost")

    sess = http_policy.outbound_session(session)
    headers: dict[str, str] = {}
    if if_none_match:
        headers["If-None-Match"] = if_none_match

    try:
        resp = sess.get(
            url,
            headers=headers,
            timeout=30,
            verify=tls_verify,
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException:
        raise RegistryFetchError("fetch_failed")

    if resp.status_code == 304:
        resp.close()
        return {"unchanged": True}

    if resp.status_code != 200:
        status = resp.status_code
        resp.close()
        raise RegistryFetchError("fetch_failed", status=status)

    etag_header = resp.headers.get("ETag")
    max_bytes = quarantine_limits.max_content_bytes()
    try:
        body = http_body.read_response_json(resp, max_bytes)
    except http_body.ResponseTooLargeError:
        raise RegistryFetchError("response_too_large")
    except http_body.ResponseReadError as exc:
        raise RegistryFetchError(exc.reason)
    except json.JSONDecodeError:
        raise RegistryFetchError("invalid_json")
    finally:
        resp.close()

    if not isinstance(body, dict):
        raise RegistryFetchError("invalid_json")

    return {"body": body, "etag": etag_header or body.get("etag")}


def _parse_nostr_snapshot(event: dict, allowlist: list[str]) -> dict:
    pubkey = str(event.get("pubkey", ""))
    if not _issuer_allowed(pubkey, allowlist):
        raise RegistryFetchError("issuer_not_on_allowlist")
    if not nostr.verify_event_signature(event):
        raise RegistryFetchError("invalid_nostr_signature")

    content = event.get("content", "")
    max_bytes = quarantine_limits.max_content_bytes()
    try:
        if isinstance(content, str):
            http_body.assert_content_within_cap(content, max_bytes)
            body = json.loads(content)
        elif isinstance(content, dict):
            # Already-decoded object (in-memory transport): bound via compact JSON size.
            packed = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
            http_body.assert_content_within_cap(packed, max_bytes)
            body = content
        else:
            raise RegistryFetchError("invalid_nostr_content")
    except http_body.ResponseTooLargeError:
        raise RegistryFetchError("response_too_large")
    except json.JSONDecodeError:
        raise RegistryFetchError("invalid_nostr_content")

    if not isinstance(body, dict):
        raise RegistryFetchError("invalid_nostr_content")
    return body


def fetch_nostr_registry(
    event_id: str,
    allowlist: list[str],
    *,
    relays: list[str] | None = None,
    transport: nostr.RelayTransport | None = None,
) -> dict:
    """Fetch registry snapshot from nostr event content."""
    eid = _resolve_event_id(event_id)
    tx = transport or nostr._default_transport()
    relay_list = nostr._load_relays(relays)
    events = tx.subscribe([{"ids": [eid]}], relays=relay_list, timeout_s=5.0)
    if not events:
        raise RegistryFetchError("nostr_event_not_found")
    event = next((ev for ev in events if str(ev.get("id", "")).lower() == eid), None)
    if event is None:
        raise RegistryFetchError("nostr_event_mismatch")
    return _parse_nostr_snapshot(event, allowlist)


def fetch_registry(
    source: str,
    allowlist: list[str] | None = None,
    *,
    if_none_match: str | None = None,
    tls_verify: bool = True,
    relays: list[str] | None = None,
    transport: nostr.RelayTransport | None = None,
    session: requests.Session | None = None,
) -> dict:
    """Fetch registry snapshot, validate, quarantine. merged is always False.

    HTTPS destinations use env host allowlist only (SCP_REGISTRY_FETCH_HOST_ALLOWLIST
    or SCP_ANTIGEN_FETCH_HOST_ALLOWLIST). Caller allowlist is issuer pubkeys for nostr.
    """
    allow = _parse_allowlist(allowlist)
    issuer_allow = http_policy.pubkey_entries(allow)

    try:
        if _is_https_source(source):
            hosts = http_policy.env_registry_host_allowlist()
            if not hosts:
                return {
                    "ok": False,
                    "error": "empty_host_allowlist",
                    "local_registry_unchanged": True,
                }
            fetched = _fetch_https(
                source,
                hosts,
                if_none_match=if_none_match,
                tls_verify=tls_verify,
                session=session,
            )
            if fetched.get("unchanged"):
                return {
                    "ok": True,
                    "unchanged": True,
                    "local_registry_unchanged": True,
                    "merged": False,
                }
            snapshot = fetched["body"]
            if fetched.get("etag") and not snapshot.get("etag"):
                snapshot = dict(snapshot)
                etag = fetched["etag"]
                if not str(etag).startswith("sha256:"):
                    etag = f"sha256:{etag}" if _HEX64.match(str(etag)) else etag
                snapshot["etag"] = etag
        else:
            if not issuer_allow:
                return {
                    "ok": False,
                    "error": "empty_allowlist",
                    "local_registry_unchanged": True,
                }
            snapshot = fetch_nostr_registry(
                source, issuer_allow, relays=relays, transport=transport
            )
    except RegistryFetchError as exc:
        return {
            "ok": False,
            "error": exc.reason,
            "local_registry_unchanged": True,
            "status": exc.status,
        }

    sv = pr.validate_snapshot(snapshot)
    if not sv["valid"]:
        return {
            "ok": False,
            "error": "invalid_snapshot",
            "errors": sv["errors"],
            "local_registry_unchanged": True,
        }

    pv = pr.validate_snapshot_patterns(snapshot["patterns"])
    if not pv["valid"]:
        antigen._audit(
            "pattern_rejected_anonymization", source=source, error_count=len(pv["errors"])
        )
        return {
            "ok": False,
            "error": "pattern_validation_failed",
            "errors": pv["errors"],
            "local_registry_unchanged": True,
        }

    diff_summary = registry_ssot.diff_snapshot(snapshot["patterns"])
    q = _write_registry_quarantine(snapshot, source=source, diff_summary=diff_summary)

    return {
        "ok": True,
        "quarantine_path": q["path"],
        "quarantine_id": q["quarantine_id"],
        "registry_version": snapshot.get("registry_version"),
        "etag": snapshot.get("etag"),
        "diff_summary": {
            "add_count": diff_summary["add_count"],
            "conflict_count": diff_summary["conflict_count"],
            "drift_max": diff_summary["drift_max"],
            "risk_breakdown": diff_summary["risk_breakdown"],
        },
        "merged": False,
    }

# PURPOSE: SCP-ANT1 Antigen P1 — nostr relay publish/subscribe for antigen announcements
#   (kind 30078) + HTTPS fetch/verify. Composes with antigen.py P0; no auto-merge.
# DEPENDENCIES: scp.antigen (sign/verify/hash), requests; optional websocket-client for relays.
# MODIFICATION NOTES: ADR 2026-06-29 — parameterized-replaceable events + content-addressed HTTPS.

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import requests

from . import antigen
from . import antigen_l402 as l402
from . import http_policy

# Parameterized-replaceable kind (30000–39999); ADR 2026-06-29 / operator lock 2026-06-30.
ANTIGEN_NOSTR_KIND = 30078
DEFAULT_RELAYS = ("wss://relay.damus.io", "wss://nos.lol")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_NSEC_RE = re.compile(r"^nsec1[02-9ac-hj-np-z]{6,}$")
_SUBSCRIBE_TIMEOUT_S = 8.0


@dataclass(frozen=True)
class AntigenAnnouncement:
    antigen_id: str
    payload_hash_bare: str
    payload_urls: tuple[str, ...]
    payload_format: str
    payload_size: int
    risk_tags: tuple[str, ...]
    schema_revision: str
    free_tier_summary: str | None
    bundle_version: int
    issuer_pubkey: str
    event_id: str
    created_at: int


class RelayTransport(Protocol):
    def publish(self, event: dict, *, relays: tuple[str, ...]) -> None: ...

    def subscribe(
        self, filters: list[dict], *, relays: tuple[str, ...], timeout_s: float
    ) -> list[dict]: ...


class FetchError(Exception):
    def __init__(self, reason: str, *, status: int | None = None, l402: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.l402 = l402


# --------------------------------------------------------------------------- env / keys

def _load_relays(relays: list[str] | None) -> tuple[str, ...]:
    if relays:
        return tuple(r.strip() for r in relays if r.strip())
    env = os.environ.get("SCP_ANTIGEN_RELAYS")
    if env:
        return tuple(r.strip() for r in env.split(",") if r.strip())
    return DEFAULT_RELAYS


def _normalize_seckey(seckey: str) -> str:
    s = seckey.strip()
    if _HEX64.match(s):
        return s
    if _NSEC_RE.match(s):
        raw = _bech32_decode(s, "nsec")
        if raw is None or len(raw) != 32:
            raise ValueError("invalid nsec bech32 seckey")
        return raw.hex()
    raise ValueError("seckey must be 64-hex or nsec1 bech32")


def seckey_from_env() -> str | None:
    env = os.environ.get("NOSTR_SECKEY")
    return _normalize_seckey(env) if env else None


# --------------------------------------------------------------------------- minimal bech32 (nsec only)

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= generators[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_decode(bech: str, expected_hrp: str) -> bytes | None:
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        return None
    hrp, data = bech[:pos], bech[pos + 1 :]
    if hrp != expected_hrp:
        return None
    try:
        decoded = [_BECH32_CHARSET.index(c) for c in data]
    except ValueError:
        return None
    if _bech32_polymod(_bech32_hrp_expand(hrp) + decoded) != 1:
        return None
    values = decoded[:-6]
    acc = 0
    count = 0
    out: list[int] = []
    for v in values:
        acc = (acc << 5) | v
        count += 5
        while count >= 8:
            count -= 8
            out.append((acc >> count) & 0xFF)
    return bytes(out)


# --------------------------------------------------------------------------- NIP-01 event crypto

def _event_template(pubkey_hex: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> list:
    return [0, pubkey_hex, created_at, kind, tags, content]


def _serialize_event_template(template: list) -> str:
    return json.dumps(template, separators=(",", ":"), ensure_ascii=False)


def compute_event_id(event: dict) -> str:
    """NIP-01 event id: sha256 of serialized unsigned template."""
    template = _event_template(
        event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]
    )
    return hashlib.sha256(_serialize_event_template(template).encode("utf-8")).hexdigest()


def verify_event_signature(event: dict) -> bool:
    if event.get("kind") != ANTIGEN_NOSTR_KIND:
        return False
    pubkey = str(event.get("pubkey", ""))
    sig = str(event.get("sig", ""))
    event_id = str(event.get("id", ""))
    if not _HEX64.match(pubkey) or not _HEX128.match(sig) or not _HEX64.match(event_id):
        return False
    if event_id != compute_event_id(event):
        return False
    return antigen._verify_schnorr(bytes.fromhex(event_id), pubkey, sig)


def sign_event(event: dict, *, seckey_hex: str) -> dict:
    """Attach id, pubkey, sig to an unsigned event dict (kind/tags/content/created_at)."""
    seckey = bytes.fromhex(_normalize_seckey(seckey_hex))
    pubkey = antigen._pubkey_hex(seckey)
    unsigned = {
        "kind": event["kind"],
        "tags": event["tags"],
        "content": event["content"],
        "created_at": event["created_at"],
    }
    unsigned["pubkey"] = pubkey
    unsigned["id"] = compute_event_id(unsigned)
    sig = antigen._sign_schnorr(bytes.fromhex(unsigned["id"]), seckey).hex()
    signed = {**unsigned, "sig": sig}
    return signed


def _bare_hash_from_manifest(manifest: dict) -> str:
    pch = str(manifest["payload_content_hash"])
    if pch.startswith("sha256:"):
        return pch[7:]
    return pch


def _tags_from_manifest(manifest: dict, payload_size: int) -> list[list[str]]:
    tags: list[list[str]] = [["d", manifest["antigen_id"]], ["x", _bare_hash_from_manifest(manifest)]]
    for url in manifest.get("payload_urls") or []:
        tags.append(["url", str(url)])
    tags.append(["m", manifest["payload_format"]])
    tags.append(["size", str(payload_size)])
    for tag in manifest.get("risk_tags") or []:
        tags.append(["t", str(tag)])
    return tags


def _content_from_manifest(manifest: dict) -> str:
    body = {
        "schema_revision": manifest["schema_revision"],
        "bundle_version": int(manifest.get("bundle_version", 0)),
    }
    if manifest.get("free_tier_summary") is not None:
        body["free_tier_summary"] = manifest["free_tier_summary"]
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def build_announcement_event(
    bundle: dict,
    *,
    seckey_hex: str,
    created_at: int | None = None,
) -> dict:
    """Build and sign a kind-30078 antigen announcement from a verified bundle."""
    manifest = bundle["manifest"]
    issuer = str(manifest.get("issuer_pubkey", "")).lower()
    v = antigen.verify_bundle(
        bundle,
        allowlist=[issuer] if _HEX64.match(issuer) else None,
        require_signature=manifest.get("signature") is not None,
    )
    if not v["ok"]:
        raise ValueError("bundle failed verification: " + ",".join(v["errors"]))
    urls = manifest.get("payload_urls") or []
    if not urls:
        raise ValueError("payload_urls required for publish")
    for url in urls:
        parsed = urlparse(str(url))
        if parsed.scheme != "https":
            raise ValueError("payload_urls must be HTTPS")

    payload_size = len(antigen._canonical_bytes(bundle["payload"]))
    unsigned = {
        "kind": ANTIGEN_NOSTR_KIND,
        "tags": _tags_from_manifest(manifest, payload_size),
        "content": _content_from_manifest(manifest),
        "created_at": int(created_at if created_at is not None else time.time()),
    }
    return sign_event(unsigned, seckey_hex=seckey_hex)


def _tag_values(tags: list[list[str]], name: str) -> list[str]:
    return [t[1] for t in tags if len(t) >= 2 and t[0] == name]


def _tag_value(tags: list[list[str]], name: str) -> str | None:
    vals = _tag_values(tags, name)
    return vals[0] if vals else None


def parse_announcement_event(event: dict) -> AntigenAnnouncement | None:
    if event.get("kind") != ANTIGEN_NOSTR_KIND:
        return None
    if not verify_event_signature(event):
        return None
    tags = event.get("tags") or []
    antigen_id = _tag_value(tags, "d")
    payload_hash = _tag_value(tags, "x")
    payload_format = _tag_value(tags, "m")
    size_raw = _tag_value(tags, "size")
    if not antigen_id or not payload_hash or not payload_format or not size_raw:
        return None
    if not _HEX64.match(payload_hash):
        return None
    try:
        payload_size = int(size_raw)
    except ValueError:
        return None
    urls = tuple(_tag_values(tags, "url"))
    if not urls:
        return None
    try:
        content = json.loads(event.get("content") or "{}")
    except json.JSONDecodeError:
        return None
    schema_revision = content.get("schema_revision")
    if schema_revision != antigen.SCHEMA_REVISION:
        return None
    return AntigenAnnouncement(
        antigen_id=antigen_id,
        payload_hash_bare=payload_hash,
        payload_urls=urls,
        payload_format=payload_format,
        payload_size=payload_size,
        risk_tags=tuple(_tag_values(tags, "t")),
        schema_revision=schema_revision,
        free_tier_summary=content.get("free_tier_summary"),
        bundle_version=int(content.get("bundle_version", 0)),
        issuer_pubkey=str(event["pubkey"]).lower(),
        event_id=str(event["id"]),
        created_at=int(event["created_at"]),
    )


def announcement_to_dict(ann: AntigenAnnouncement) -> dict:
    return {
        "antigen_id": ann.antigen_id,
        "payload_hash": f"sha256:{ann.payload_hash_bare}",
        "payload_urls": list(ann.payload_urls),
        "payload_format": ann.payload_format,
        "payload_size": ann.payload_size,
        "risk_tags": list(ann.risk_tags),
        "schema_revision": ann.schema_revision,
        "free_tier_summary": ann.free_tier_summary,
        "bundle_version": ann.bundle_version,
        "issuer_pubkey": ann.issuer_pubkey,
        "event_id": ann.event_id,
        "created_at": ann.created_at,
    }


# --------------------------------------------------------------------------- relay transport

class InMemoryRelayTransport:
    """Test double: single-process relay store."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, event: dict, *, relays: tuple[str, ...]) -> None:
        self.events.append(dict(event))

    def subscribe(
        self, filters: list[dict], *, relays: tuple[str, ...], timeout_s: float
    ) -> list[dict]:
        del relays, timeout_s
        out: list[dict] = []
        for ev in self.events:
            if _event_matches_filters(ev, filters):
                out.append(ev)
        return out


def _event_matches_filters(event: dict, filters: list[dict]) -> bool:
    for f in filters:
        kinds = f.get("kinds")
        if kinds and event.get("kind") not in kinds:
            continue
        authors = f.get("authors")
        if authors and event.get("pubkey") not in authors:
            continue
        since = f.get("since")
        if since is not None and int(event.get("created_at", 0)) < int(since):
            continue
        until = f.get("until")
        if until is not None and int(event.get("created_at", 0)) > int(until):
            continue
        tag_filters = {k: v for k, v in f.items() if len(k) == 2 and k.startswith("#")}
        if tag_filters:
            tags = event.get("tags") or []
            matched = True
            for key, want in tag_filters.items():
                tag_name = key[1]
                have = _tag_values(tags, tag_name)
                if isinstance(want, list):
                    if not any(w in have for w in want):
                        matched = False
                        break
                elif want not in have:
                    matched = False
                    break
            if not matched:
                continue
        return True
    return False


def _require_websocket_client():
    try:
        import websocket  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "websocket-client is required for live nostr relays. "
            "Install with: pip install 'scp-mcp[antigen-nostr]'"
        ) from exc
    return websocket


class WebSocketRelayTransport:
    def publish(self, event: dict, *, relays: tuple[str, ...]) -> None:
        ws = _require_websocket_client()
        msg = json.dumps(["EVENT", event])
        errors: list[str] = []
        for relay in relays:
            try:
                conn = ws.create_connection(relay, timeout=10)
                try:
                    conn.send(msg)
                    conn.recv()
                finally:
                    conn.close()
            except Exception as exc:
                errors.append(f"{relay}: {exc}")
        if errors and len(errors) == len(relays):
            raise RuntimeError("publish failed on all relays: " + "; ".join(errors))

    def subscribe(
        self, filters: list[dict], *, relays: tuple[str, ...], timeout_s: float
    ) -> list[dict]:
        ws = _require_websocket_client()
        sub_id = uuid.uuid4().hex
        req = json.dumps(["REQ", sub_id, *filters])
        seen: dict[str, dict] = {}
        deadline = time.time() + timeout_s
        for relay in relays:
            if time.time() >= deadline:
                break
            try:
                conn = ws.create_connection(relay, timeout=min(10, timeout_s))
                try:
                    conn.settimeout(max(0.5, deadline - time.time()))
                    conn.send(req)
                    while time.time() < deadline:
                        try:
                            raw = conn.recv()
                        except Exception:
                            break
                        if not raw:
                            break
                        try:
                            frame = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(frame, list) or not frame:
                            continue
                        if frame[0] == "EVENT" and len(frame) >= 3:
                            ev = frame[2]
                            if isinstance(ev, dict) and ev.get("id"):
                                seen[str(ev["id"])] = ev
                        elif frame[0] == "EOSE" and len(frame) >= 2 and frame[1] == sub_id:
                            break
                finally:
                    conn.close()
            except Exception:
                continue
        return list(seen.values())


def _default_transport() -> RelayTransport:
    return WebSocketRelayTransport()


# --------------------------------------------------------------------------- publish / discover

def publish_announcement(
    bundle: dict,
    *,
    seckey_hex: str | None = None,
    relays: list[str] | None = None,
    transport: RelayTransport | None = None,
    dry_run: bool = False,
) -> dict:
    key = _normalize_seckey(seckey_hex or seckey_from_env() or "")
    if not key:
        raise ValueError("seckey_hex or NOSTR_SECKEY required for publish")
    relay_list = _load_relays(relays)
    event = build_announcement_event(bundle, seckey_hex=key)
    manifest = bundle["manifest"]
    if dry_run:
        antigen._audit(
            "nostr_publish_dry_run",
            antigen_id=manifest["antigen_id"],
            payload_hash=manifest["payload_content_hash"],
            event_id=event["id"],
        )
        return {"published": False, "dry_run": True, "event": event, "relays": list(relay_list)}

    tx = transport or _default_transport()
    tx.publish(event, relays=relay_list)
    antigen._audit(
        "nostr_publish",
        antigen_id=manifest["antigen_id"],
        payload_hash=manifest["payload_content_hash"],
        event_id=event["id"],
        relay_count=len(relay_list),
    )
    return {"published": True, "dry_run": False, "event_id": event["id"], "relays": list(relay_list)}


def discover_announcements(
    *,
    allowlist: list[str] | None = None,
    relays: list[str] | None = None,
    antigen_id: str | None = None,
    since: int | None = None,
    until: int | None = None,
    transport: RelayTransport | None = None,
    timeout_s: float = _SUBSCRIBE_TIMEOUT_S,
) -> list[AntigenAnnouncement]:
    allow = antigen._load_allowlist(allowlist)
    if not allow:
        return []

    authors = sorted({a.lower() for a in allow if _HEX64.match(a.lower())})
    if not authors:
        return []

    filt: dict[str, Any] = {"kinds": [ANTIGEN_NOSTR_KIND], "authors": authors}
    if since is not None:
        filt["since"] = int(since)
    if until is not None:
        filt["until"] = int(until)
    if antigen_id:
        filt["#d"] = [antigen_id]

    relay_list = _load_relays(relays)
    tx = transport or _default_transport()
    raw_events = tx.subscribe([filt], relays=relay_list, timeout_s=timeout_s)

    out: list[AntigenAnnouncement] = []
    for ev in raw_events:
        ann = parse_announcement_event(ev)
        if ann is None:
            continue
        if ann.issuer_pubkey not in allow:
            continue
        out.append(ann)

    antigen._audit("nostr_discover", count=len(out), relay_count=len(relay_list))
    return out


# --------------------------------------------------------------------------- HTTPS fetch + bundle compose

def _extract_payload_obj(body: dict) -> dict:
    if "payload" in body and "manifest" in body:
        return body["payload"]
    if "patterns" in body:
        return body
    raise FetchError("unrecognized_payload_shape")


def _build_l402_metadata(resp: requests.Response) -> dict:
    www_auth = resp.headers.get("WWW-Authenticate")
    parsed_challenge = l402.parse_www_authenticate_l402(www_auth)
    meta: dict = {
        "status": 402,
        "www_authenticate": www_auth,
    }
    if parsed_challenge:
        meta["macaroon"] = parsed_challenge.get("macaroon")
        meta["invoice"] = parsed_challenge.get("invoice")
        meta["invoice_hint"] = parsed_challenge.get("invoice_hint")
    return meta


def _resolve_fetch_host_allowlist(host_allowlist: list[str] | None) -> list[str]:
    if host_allowlist is not None:
        return [h.strip() for h in host_allowlist if h and h.strip()]
    env = os.environ.get("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "")
    return [a.strip() for a in env.split(",") if a.strip()]


def _fetch_response(
    sess: requests.Session,
    url: str,
    *,
    l402_token: str | None = None,
) -> requests.Response:
    verify_tls = os.environ.get("SCP_ANTIGEN_TLS_VERIFY", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    )
    if l402_token:
        macaroon, preimage = l402.normalize_l402_token(l402_token)
        headers = {"Authorization": l402.format_authorization_header(macaroon, preimage)}
        return sess.get(
            url, timeout=30, headers=headers, verify=verify_tls, allow_redirects=False
        )
    return sess.get(url, timeout=30, verify=verify_tls, allow_redirects=False)


def _process_fetch_response(
    resp: requests.Response,
    *,
    url_host: str,
    expected_hash_bare_hex: str,
    antigen_id: str | None = None,
    l402_retry: bool = False,
) -> dict:
    expected = f"sha256:{expected_hash_bare_hex}"
    if resp.status_code != 200:
        antigen._audit(
            "fetch_rejected",
            url_host=url_host,
            payload_hash=expected,
            status=resp.status_code,
            antigen_id=antigen_id,
        )
        raise FetchError("http_error", status=resp.status_code)

    if l402_retry:
        antigen._audit(
            "fetch_l402_retry",
            url_host=url_host,
            payload_hash=expected,
            antigen_id=antigen_id,
        )

    try:
        body = resp.json()
    except json.JSONDecodeError as exc:
        antigen._audit(
            "fetch_rejected",
            url_host=url_host,
            payload_hash=expected,
            reason="invalid_json",
            antigen_id=antigen_id,
        )
        raise FetchError("invalid_json") from exc

    payload = _extract_payload_obj(body)
    actual = antigen.compute_payload_hash(payload)
    if actual != expected:
        antigen._audit(
            "fetch_rejected",
            url_host=url_host,
            payload_hash=expected,
            reason="hash_mismatch",
            antigen_id=antigen_id,
        )
        raise FetchError("hash_mismatch")

    antigen._audit(
        "fetch_ok",
        url_host=url_host,
        payload_hash=expected,
        antigen_id=antigen_id,
    )
    return payload


def fetch_payload(
    url: str,
    expected_hash_bare_hex: str,
    *,
    l402_token: str | None = None,
    antigen_id: str | None = None,
    session: requests.Session | None = None,
    host_allowlist: list[str] | None = None,
) -> dict:
    """Fetch HTTPS payload, verify sha256 (bare hex).

    On 402 without l402_token, raise FetchError with parsed L402 challenge metadata.
    When l402_token is supplied, send Authorization on the request (operator-paid retry).

    Production: host must be on SCP_ANTIGEN_FETCH_HOST_ALLOWLIST or host_allowlist
    (fail-closed). Regtest envs use localhost assert instead.
    """
    if not _HEX64.match(expected_hash_bare_hex):
        raise FetchError("bad_expected_hash")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FetchError("url_must_be_https")
    if l402.regtest_fetch_hardening_enabled():
        try:
            l402.assert_localhost_fetch_url(url)
        except ValueError:
            raise FetchError("fetch_url_not_localhost")
    else:
        hosts = _resolve_fetch_host_allowlist(host_allowlist)
        if not http_policy.host_allowed(url, hosts):
            raise FetchError("host_not_on_allowlist")

    token = l402_token or l402.l402_token_from_env()
    sess = http_policy.outbound_session(session)
    try:
        resp = _fetch_response(sess, url, l402_token=token)
    except ValueError as exc:
        raise FetchError("invalid_l402_token") from exc

    if resp.status_code == 402:
        meta = _build_l402_metadata(resp)
        antigen._audit(
            "fetch_l402_challenge",
            url_host=parsed.netloc,
            payload_hash=f"sha256:{expected_hash_bare_hex}",
            invoice_hint=meta.get("invoice_hint"),
            antigen_id=antigen_id,
        )
        if token:
            antigen._audit(
                "fetch_l402_retry_failed",
                url_host=parsed.netloc,
                payload_hash=f"sha256:{expected_hash_bare_hex}",
                invoice_hint=meta.get("invoice_hint"),
                antigen_id=antigen_id,
            )
        raise FetchError("payment_required", status=402, l402=meta)

    return _process_fetch_response(
        resp,
        url_host=parsed.netloc,
        expected_hash_bare_hex=expected_hash_bare_hex,
        antigen_id=antigen_id,
        l402_retry=bool(token),
    )


def bundle_from_announcement(announcement: AntigenAnnouncement, payload: dict) -> dict:
    manifest: dict[str, Any] = {
        "schema_revision": announcement.schema_revision,
        "antigen_id": announcement.antigen_id,
        "bundle_version": announcement.bundle_version,
        "issuer_pubkey": announcement.issuer_pubkey,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(announcement.created_at)),
        "payload_content_hash": f"sha256:{announcement.payload_hash_bare}",
        "payload_format": announcement.payload_format,
        "payload_urls": list(announcement.payload_urls),
    }
    if announcement.free_tier_summary is not None:
        manifest["free_tier_summary"] = announcement.free_tier_summary
    if announcement.risk_tags:
        manifest["risk_tags"] = list(announcement.risk_tags)
    return {"manifest": manifest, "payload": payload}


def import_from_announcement(
    announcement: AntigenAnnouncement,
    *,
    allowlist: list[str] | None = None,
    l402_token: str | None = None,
    session: requests.Session | None = None,
) -> dict:
    """Fetch first URL, verify hash, assemble bundle, quarantine via import_bundle (no merge)."""
    allow = antigen._load_allowlist(allowlist)
    if announcement.issuer_pubkey not in allow:
        antigen._audit("import_rejected", payload_hash=f"sha256:{announcement.payload_hash_bare}",
                       reasons=["issuer_not_on_allowlist"])
        return {
            "accepted": False,
            "rejected": True,
            "reasons": ["issuer_not_on_allowlist"],
            "payload_hash": f"sha256:{announcement.payload_hash_bare}",
        }
    token = l402_token or l402.l402_token_from_env()
    try:
        payload = fetch_payload(
            announcement.payload_urls[0],
            announcement.payload_hash_bare,
            l402_token=token,
            antigen_id=announcement.antigen_id,
            session=session,
        )
    except FetchError as exc:
        return {
            "accepted": False,
            "rejected": True,
            "reasons": [exc.reason],
            "payload_hash": f"sha256:{announcement.payload_hash_bare}",
            "l402": exc.l402,
        }
    bundle = bundle_from_announcement(announcement, payload)
    return antigen.import_bundle(
        bundle,
        allowlist=list(allow),
        require_signature=False,
        source="antigen_nostr_discover",
    )

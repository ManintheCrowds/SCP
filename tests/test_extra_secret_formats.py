# PURPOSE: Additional secret formats are masked in full, including quoted phrases.

from __future__ import annotations

from scp import mask_secrets


def _project() -> str:
    return "sk-" + "proj-" + ("p" * 24)


def test_quoted_password_redacts_every_word() -> None:
    out = mask_secrets.mask('password: "hello world"')
    assert out == 'password: "[REDACTED]"'
    assert "hello" not in out
    assert "world" not in out


def test_json_password_keeps_the_key() -> None:
    out = mask_secrets.mask('{"password": "hello world"}')
    assert out == '{"password": "[REDACTED]"}'


def test_wordpress_db_password_redacts_the_value() -> None:
    out = mask_secrets.mask("define('DB_PASSWORD', 'db pass phrase');")
    assert "db pass phrase" not in out
    assert "DB_PASSWORD" in out
    assert "[REDACTED]" in out


def test_project_key_and_jwt_are_removed() -> None:
    project = _project()
    token = "ey" + "J" + ("a" * 12) + "." + ("b" * 12) + "." + ("c" * 12)
    out = mask_secrets.mask(f"{project} {token}")
    assert project not in out
    assert token not in out

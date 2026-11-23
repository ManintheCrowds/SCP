# PURPOSE: An assignment value that wraps through '/' or '+' stays masked.

from __future__ import annotations

from scp import mask_secrets


def _chunk(length: int, salt: int, mark: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    state = salt & 0xFFFFFFFF
    chars: list[str] = []
    for index in range(length):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    if length:
        chars[salt % length] = mark
    return "".join(chars)


def _leaks(text: str, second: str) -> bool:
    masked = mask_secrets.mask(text)
    try:
        outbound = mask_secrets.prepare_outbound(text)
    except mask_secrets.EgressMaskError:
        outbound = ""
    return second in masked or second in outbound


def test_slash_at_the_split_does_not_leave_the_second_half() -> None:
    first = _chunk(20, 4, "/")
    second = _chunk(20, 8, "A")
    leaked = 0
    for label in ("AWS_SECRET_ACCESS_KEY=", "SecretAccessKey:"):
        text = label + first + "\n" + second
        if _leaks(text, second):
            leaked += 1
    assert leaked == 0


def test_quoted_secret_access_key_forms_are_masked() -> None:
    leaked = 0
    total = 0
    for salt in range(20):
        value = _chunk(40, salt + 3, "A")
        forms = (
            '{"SecretAccessKey": "' + value + '"}',
            "SecretAccessKey: " + value,
            "SecretAccessKey: '" + value + "'",
        )
        for text in forms:
            total += 1
            if _leaks(text, value):
                leaked += 1
    assert total == 60
    assert leaked == 0


def _key_id(salt: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    state = salt & 0xFFFFFFFF
    chars: list[str] = []
    for index in range(16):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    return ("AK" + "IA") + "".join(chars)


def _value_visible(text: str, value: str) -> bool:
    masked = mask_secrets.mask(text)
    try:
        outbound = mask_secrets.prepare_outbound(text)
    except mask_secrets.EgressMaskError:
        outbound = ""
    return any(
        value[index : index + 8] in masked or value[index : index + 8] in outbound
        for index in range(0, len(value) - 7)
    )


def test_shared_credentials_csv_and_tabs_are_masked() -> None:
    leaked = 0
    total = 0
    label = "aws_secret_" + "access_key"
    for salt in range(20):
        chars = list(_chunk(40, salt + 21, "A"))
        chars[20] = "/"
        value = "".join(chars)
        key_id = _key_id(salt + 4)
        forms = (
            "[profile]\n" + label + " = " + value + "\n",
            "Access key ID,Secret access key\n" + key_id + "," + value + "\n",
            key_id + "\t" + value + "\n",
            label + "\t" + value + "\n",
        )
        for text in forms:
            total += 1
            if _value_visible(text, value):
                leaked += 1
    assert total == 80
    assert leaked == 0


def test_quoted_and_reordered_aws_rows_are_masked() -> None:
    leaked = 0
    total = 0
    user = "alice"
    for salt in range(20):
        chars = list(_chunk(40, salt + 40, "A"))
        chars[20] = "/"
        value = "".join(chars)
        key_id = _key_id(salt + 70)
        forms = (
            '"' + key_id + '","' + value + '"',
            '"' + key_id + '",' + value,
            '"' + user + '","' + key_id + '","' + value + '","https://example.test/console","ok"',
            value + "," + key_id,
            key_id + "," + user + "," + value,
            value + "\t" + key_id,
            key_id + "\t" + user + "\t" + value,
        )
        for text in forms:
            total += 1
            if _value_visible(text, value):
                leaked += 1
    assert total == 140
    assert leaked == 0


def test_windows_excel_aws_rows_are_masked() -> None:
    """CRLF, a BOM, or a zero-width space must not skip the row masker."""
    leaked = 0
    total = 0
    bom = "\ufeff"
    zwsp = "\u200b"
    user = "alice"
    for salt in range(20):
        chars = list(_chunk(40, salt + 90, "A"))
        chars[20] = "/"
        value = "".join(chars)
        key_id = _key_id(salt + 110)
        quoted = '"' + key_id + '","' + value + '"'
        reordered = '"' + value + '","' + key_id + '"'
        excel = (
            '"' + user + '","' + key_id + '","' + value
            + '","https://example.test/console","ok"'
        )
        header = '"Access key ID","Secret access key"'
        forms = (
            header + "\r\n" + quoted + "\r\n",
            header + "\r\n" + reordered + "\r\n",
            header + "\r\n" + excel + "\r\n",
            bom + quoted,
            bom + value + "," + key_id,
            value + "," + key_id + "\r\n",
            value + "\t" + key_id + "\r\n",
            header[:8] + zwsp + header[8:] + "\n" + quoted,
            header + "\r" + quoted + "\n",
        )
        for text in forms:
            total += 1
            if _value_visible(text, value):
                leaked += 1
    assert total == 180
    assert leaked == 0


def test_a_split_key_id_is_detected_and_masked() -> None:
    """mask and has_secrets agree when a quoted newline splits the key id."""
    chars = list(_chunk(40, 7, "A"))
    chars[20] = "/"
    value = "".join(chars)
    key_id = _key_id(9)
    text = '"' + key_id + '\n","' + value + '"'
    assert mask_secrets.has_secrets(text) is True
    assert not _value_visible(text, value)


def test_a_quoted_aws_secret_may_span_lines() -> None:
    leaked = 0
    total = 0
    for salt in range(20):
        chars = list(_chunk(40, salt + 140, "A"))
        chars[20] = "/"
        value = "".join(chars)
        key_id = _key_id(salt + 180)
        forms = (
            '"' + key_id + '","' + value[:20] + "\n" + value[20:] + '"',
            '"' + key_id + '","' + value[:20] + "\r\n" + value[20:] + '"',
            '"' + key_id + '","\n' + value + '"',
            '"' + key_id + '\n","' + value + '"',
        )
        for text in forms:
            total += 1
            if _value_visible(text, value):
                leaked += 1
    assert total == 80
    assert leaked == 0


def test_sts_xml_and_escaped_json_are_masked() -> None:
    leaked = 0
    total = 0
    label = "Secret" + "Access" + "Key"
    for salt in range(10):
        value = _chunk(40, salt + 11, "A")
        forms = (
            "<" + label + ">" + value + "</" + label + ">",
            '\\"' + label + '\\": \\"' + value + '\\"',
        )
        for text in forms:
            total += 1
            masked = mask_secrets.mask(text)
            try:
                outbound = mask_secrets.prepare_outbound(text)
            except mask_secrets.EgressMaskError:
                outbound = ""
            if any(
                value[index : index + 8] in masked or value[index : index + 8] in outbound
                for index in range(0, len(value) - 7)
            ):
                leaked += 1
    assert total == 20
    assert leaked == 0


def test_shell_and_powershell_secrets_survive_every_slash_and_plus() -> None:
    leaked = 0
    total = 0
    shell = "export " + "AWS_" + "SECRET_" + "ACCESS_" + "KEY='"
    powershell = "$env:" + "AWS_" + "SECRET_" + "ACCESS_" + "KEY='"
    for salt, prefix in enumerate((shell, powershell)):
        for mark in ("/", "+"):
            for position in range(40):
                value = _chunk(40, salt * 80 + position, "A")
                chars = list(value)
                chars[position] = mark
                secret = "".join(chars)
                text = prefix + secret + "'"
                total += 1
                masked = mask_secrets.mask(text)
                try:
                    outbound = mask_secrets.prepare_outbound(text)
                except mask_secrets.EgressMaskError:
                    outbound = ""
                if any(
                    secret[index : index + 8] in masked or secret[index : index + 8] in outbound
                    for index in range(0, len(secret) - 7)
                ):
                    leaked += 1
    assert total == 160
    assert leaked == 0


def test_random_slash_and_plus_splits_stay_masked() -> None:
    leaked = 0
    total = 0
    for salt in range(40):
        for mark in ("/", "+"):
            first = _chunk(20, salt, mark)
            second = _chunk(20, salt + 50, mark)
            text = "AWS_SECRET_ACCESS_KEY=" + first + "\n" + second
            total += 1
            if _leaks(text, second):
                leaked += 1
    assert total == 80
    assert leaked == 0

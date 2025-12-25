import re
from dataclasses import dataclass


_HEX_CHARS_RE = re.compile(r"[^0-9a-fA-F]")


def _normalize_hex_string(s: str) -> str:
    if s is None:
        return ""
    s = s.strip()
    if not s:
        return ""
    s = re.sub(r"0x", "", s, flags=re.IGNORECASE)
    s = _HEX_CHARS_RE.sub("", s)
    return s


def parse_hex_bytes(s: str) -> bytes:
    hexchars = _normalize_hex_string(s)
    if not hexchars:
        return b""
    if len(hexchars) % 2 != 0:
        raise ValueError("Hex string has odd length after normalization")
    return bytes.fromhex(hexchars)


def hex_to_text(hex_string: str, encoding: str = "utf-8", errors: str = "replace") -> str:
    b = parse_hex_bytes(hex_string)
    if not b:
        return ""
    return b.decode(encoding, errors=errors)


def text_to_hex(text: str, encoding: str = "utf-8", uppercase: bool = True, sep: str = " ") -> str:
    if text is None or text == "":
        return ""
    b = text.encode(encoding)
    fmt = "{:02X}" if uppercase else "{:02x}"
    return sep.join(fmt.format(x) for x in b)


def hex_to_int(hex_string: str) -> int:
    if hex_string is None:
        raise ValueError("Empty input")

    s = hex_string.strip()
    if not s:
        raise ValueError("Empty input")

    neg = s.startswith("-")
    if neg:
        s = s[1:].strip()

    s = re.sub(r"^0x", "", s, flags=re.IGNORECASE)
    s = _normalize_hex_string(s)

    if not s:
        raise ValueError("No hex digits found")

    v = int(s, 16)
    return -v if neg else v


@dataclass(frozen=True)
class ConversionResult:
    ok: bool
    output: str
    error: str = ""


def safe_hex_to_text(hex_string: str, encoding: str = "utf-8") -> ConversionResult:
    try:
        return ConversionResult(True, hex_to_text(hex_string, encoding=encoding))
    except Exception as e:
        return ConversionResult(False, "", str(e))


def safe_text_to_hex(text: str, encoding: str = "utf-8", uppercase: bool = True, sep: str = " ") -> ConversionResult:
    try:
        return ConversionResult(True, text_to_hex(text, encoding=encoding, uppercase=uppercase, sep=sep))
    except Exception as e:
        return ConversionResult(False, "", str(e))


def safe_hex_to_int(hex_string: str) -> ConversionResult:
    try:
        return ConversionResult(True, str(hex_to_int(hex_string)))
    except Exception as e:
        return ConversionResult(False, "", str(e))

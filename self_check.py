import sys

from converters import hex_to_int, hex_to_text, parse_hex_bytes, text_to_hex


def _assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg} expected={b!r} got={a!r}")


def run() -> int:
    _assert_eq(hex_to_text("41 42 43", encoding="ascii"), "ABC", "hex2asc")
    _assert_eq(hex_to_text("414243", encoding="ascii"), "ABC", "hex2asc")
    _assert_eq(text_to_hex("ABC", encoding="ascii"), "41 42 43", "asc2hex")
    _assert_eq(text_to_hex("ABC", encoding="ascii", sep=""), "414243", "asc2hex")

    _assert_eq(hex_to_int("FF"), 255, "hex2int")
    _assert_eq(hex_to_int("0x10"), 16, "hex2int")
    _assert_eq(hex_to_int("-0x2A"), -42, "hex2int")

    _assert_eq(parse_hex_bytes(""), b"", "parse_hex_bytes")
    _assert_eq(parse_hex_bytes("0x00 01"), b"\x00\x01", "parse_hex_bytes")

    try:
        parse_hex_bytes("F")
        raise AssertionError("odd length should fail")
    except ValueError:
        pass

    try:
        hex_to_int("--")
        raise AssertionError("invalid should fail")
    except ValueError:
        pass

    return 0


if __name__ == "__main__":
    try:
        code = run()
    except Exception as e:
        print(f"SELF_CHECK_FAIL: {e}")
        sys.exit(2)
    print("SELF_CHECK_OK")
    sys.exit(code)

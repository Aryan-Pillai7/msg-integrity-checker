"""pytest tests for integrity.py."""
import hashlib
import hmac

from integrity import make_tag, run_scenarios, tamper, verify

KEY = "secret123"
MSG = "Pay Bob $100"


def test_valid_tag_verifies():
    assert verify(KEY, MSG, make_tag(KEY, MSG))


def test_changed_message_fails():
    tag = make_tag(KEY, MSG)
    assert not verify(KEY, tamper(MSG), tag)
    assert not verify(KEY, MSG + " ", tag)


def test_wrong_key_fails():
    tag = make_tag(KEY, MSG)
    assert not verify("wrongkey", MSG, tag)


def test_tag_is_64_hex_chars():
    tag = make_tag(KEY, MSG)
    assert len(tag) == 64
    assert all(c in "0123456789abcdef" for c in tag)


def test_matches_rfc4231_vector():
    # RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    assert make_tag("Jefe", "what do ya want for nothing?") == expected


def test_matches_raw_hmac():
    assert make_tag(KEY, MSG) == hmac.new(KEY.encode(), MSG.encode(), hashlib.sha256).hexdigest()


def test_scenarios_outcomes():
    results = [ok for _, _, _, ok in run_scenarios(KEY, MSG)]
    assert results == [True, False, False]
